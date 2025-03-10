// Binary ip.wtf provides a server that reports the IP address of the client.
package main

// © David Leadbeater <http://©.st/dgl>
// SPDX-License-Identifier: 0BSD

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/oschwald/geoip2-golang"
	"github.com/pires/go-proxyproto"
	"github.com/pires/go-proxyproto/tlvparse"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	flagListen         = flag.String("listen", ":8080", "[ip]:port to listen for HTTP connections on")
	flagHost           = flag.String("host", "ip.wtf", "Hostname for the overall application")
	flagV4Host         = flag.String("v4-host", "127.0.0.1:8080", "Host for IPv4 access")
	flagV6Host         = flag.String("v6-host", "[::1]:8080", "Host for IPv6 access")
	flagMaxMindDB      = flag.String("maxmind-db", "GeoLite2-City.mmdb", "MaxMind IP database")
	flagMaxMindDBASN   = flag.String("maxmind-db-asn", "GeoLite2-ASN.mmdb", "MaxMind IP database for ASN")
	flagAllowedMetrics = flag.String("allowed-metrics", "127.0.0.0/8,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8,::1/128", "IPs allowed to fetch metrics")
	flagProxySupport   = flag.Bool("proxy-protocol", false, "Enable proxy protocol support on listener")
	flagLocation       = flag.String("location", "", "Location of this node")
	flagVersion        = flag.Bool("version", false, "Display version")
)

var allowedMetrics []net.IPNet
var promhttpHandler = promhttp.Handler()

var (
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "http",
			Name:      "requests_total",
		},
		[]string{"code", "method", "handler"})
)

func init() {
	prometheus.MustRegister(httpRequests)
}

var mmDB *geoip2.Reader
var mmDBASN *geoip2.Reader

var ipTmpl = template.Must(template.ParseFS(content, "ip.html"))

// RecordingListener wraps a net.Listener and wraps the resulting accepted
// connections in a RecordingConn.
type RecordingListener struct {
	net.Listener
}

func (l RecordingListener) Accept() (net.Conn, error) {
	rw, err := l.Listener.Accept()
	var header *proxyproto.Header
	if *flagProxySupport {
		if pconn, ok := rw.(*proxyproto.Conn); ok {
			header = pconn.ProxyHeader()
		}
	}
	return RecordingConn{Conn: rw, read: &readInfo{}, Header: header}, err
}

// RecordingConn wraps a net.Conn and records the data returned by Read.
type RecordingConn struct {
	net.Conn
	read   *readInfo
	Header *proxyproto.Header
}

type readInfo struct {
	read  []byte
	count int
}

func (c RecordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	// Store the data returned by Read.
	c.read.read = append(c.read.read, b[:n]...)
	return n, err
}

type contextKey struct {
	key string
}

var ConnContextKey = &contextKey{"conn"}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ConnContextKey, c)
}

type Type int

const (
	Html = iota
	Plain
	Json
)

func resolveAccept(req *http.Request) Type {
	if req.URL.Path == "/fun/reverse" {
		return Html
	}

	accepts := strings.Split(req.Header.Get("Accept"), ",")
ACCEPT:
	for _, accept := range accepts {
		switch i := strings.Split(strings.TrimSpace(accept), ";"); i[0] {
		case "text/html":
			return Html
		case "text/plain":
			return Plain
		case "application/json":
			return Json
		case "*/*":
			break ACCEPT
		}
	}
	ua := req.Header.Get("User-Agent")
	if strings.Contains(ua, "curl/") || strings.Contains(ua, "Wget/") || strings.Contains(ua, " WindowsPowerShell/") {
		return Plain
	}
	if mode := req.Header.Get("Sec-Fetch-Mode"); mode == "cors" {
		return Plain
	}
	if !strings.Contains(ua, "/") && len(accepts) == 1 && accepts[0] == "" {
		// No Accept header and User-Agent doesn't look like a real browser.
		return Plain
	}
	return Html
}

func hostRouter(w http.ResponseWriter, req *http.Request, conn *RecordingConn) {
	if strings.Contains(req.Host, ".dns."+*flagHost) {
		dnsHandler(w, req)
	} else if req.URL.Path == "/" {
		ip(w, req, conn)
	} else if len(req.URL.Path) <= 1 {
		log.Printf("Bad request, weird path: %q", req.URL.Path)
		http.Error(w, "Bad request", http.StatusBadRequest)
	} else if ip := net.ParseIP(req.URL.Path[1:]); ip != nil {
		ipDetails(w, req, conn, false)
	} else {
		log.Printf("Not found: %q", req.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

func connWrap(handler func(w http.ResponseWriter, req *http.Request, conn *RecordingConn)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		v := req.Context().Value(ConnContextKey)
		rConn := v.(RecordingConn)
		rConn.read.count += 1
		handler(w, req, &rConn)
		rConn.read.read = nil
	}
}

func ip(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)

	ua := req.Header.Get("User-Agent")
	curl := strings.Contains(ua, "curl/")
	if !curl {
		w.Header().Add("X-Super-Cow-Powers", "curl "+*flagHost+"/moo")
		w.Header().Add("Cache-Control", "no-store")
	}

	switch resolveAccept(req) {
	case Plain:
		if !curl {
			w.Header().Add("Access-Control-Allow-Origin", "*")
			w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		} else {
			w.Header().Add("Trailer", "X-Escape, \x1b[G\x1b[K\x1b[F\x1b[10G\x1b[32m200\x1b[m")
			w.Header().Add("X-Zz", "\x1b[G\x1b[K\x1b[F\x1b[K\x1b[F")
		}
		w.Write([]byte(remoteAddr.IP.String() + "\n"))
		if curl {
			ip := lookupIP(remoteAddr.IP)
			var escape, emoji strings.Builder
			for _, char := range ip.Location.Country {
				emoji.WriteRune(rune(char) + 0x1F1A5)
			}
			escape.WriteString("\x1b[G\x1b[K")
			escape.WriteString("\x1b[G\x1b[3A\x1b[M\x1b[B\x1b[1m\x1b[48;2;0;0;0m\x1b[38;2;255;255;255m\x1b#3")
			escape.WriteString(remoteAddr.IP.String())
			escape.WriteString("    ")
			escape.WriteString(emoji.String())
			escape.WriteString("\x1b[B\x1b[G\x1b#4")
			escape.WriteString(remoteAddr.IP.String())
			escape.WriteString("    ")
			escape.WriteString(emoji.String())
			escape.WriteString("\x1b[m\x1b[B")
			w.Header().Set("X-Escape", escape.String())
		}
		return
	case Json:
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		req.URL.Path = "/" + remoteAddr.IP.String()
		ipDetails(w, req, rConn, curl)
		return
	}

	var dnsID strings.Builder
	b32 := base32.NewEncoder(base32.HexEncoding.WithPadding(base32.NoPadding), &dnsID)
	_, err := io.CopyN(b32, rand.Reader, 12)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b32.Close()

	var sslVersion string
	var sslCipher string
	if rConn.Header != nil {
		sslTLV, err := extractSSL(rConn.Header)
		if err != nil {
			log.Printf("extractSSL failed, ignoring: %v", err)
		} else if sslTLV != nil {
			sslVersion, _ = sslTLV.SSLVersion()
			sslCipher, _ = sslTLV.SSLCipher()
		}
	}

	ip4 := remoteAddr.IP.To4()
	strIp4 := ""
	if ip4 != nil {
		strIp4 = ip4.String()
	}

	err = ipTmpl.Execute(w, map[string]interface{}{
		"IPv4":       ip4,
		"IPv6":       remoteAddr.IP,
		"RIPv4":      Reverse(strIp4),
		"RIPv6":      Reverse(remoteAddr.IP.String()),
		"RemoteAddr": remoteAddr,
		"Details": map[string]interface{}{
			remoteAddr.IP.String(): lookupIP(remoteAddr.IP),
		},
		"TLS":          sslVersion,
		"TLSCipher":    sslCipher,
		"RequestCount": rConn.read.count,
		"Request":      string(rConn.read.read),
		"RawRequest":   req,
		"Host":         *flagHost,
		"V4Host":       *flagV4Host,
		"V6Host":       *flagV6Host,
		"DNSHost":      ".dns." + *flagHost,
		"DNSID":        dnsID.String(),
		"NodeLocation": *flagLocation,
		"Devel":        len(*flagLocation) == 0,
	})

	if err != nil {
		log.Printf("templating failed: %v", err)
		http.Error(w, "Failed rendering template", http.StatusInternalServerError)
	}
}

func ipDetails(w http.ResponseWriter, req *http.Request, rConn *RecordingConn, curl bool) {
	ip := net.ParseIP(req.URL.Path[1:])
	if ip == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	e := json.NewEncoder(w)
	if curl {
		e.SetIndent("", "  ")
	}
	err := e.Encode(lookupIP(ip))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func lookupIP(ip net.IP) (result *IPResult) {
	result = &IPResult{
		IP: ip.String(),
	}

	var shortIP net.IP
	if v4 := ip.To4(); v4 != nil {
		shortIP = v4
	} else {
		shortIP = ip
	}

	if mmDB != nil {
		record, err := mmDB.City(shortIP)
		if err != nil {
			log.Printf("MaxMind lookup for %v: %v", shortIP, err)
		} else {
			if record.Country.IsoCode != "" {
				regionName := ""
				region := ""
				if len(record.Subdivisions) > 0 {
					regionName = record.Subdivisions[len(record.Subdivisions)-1].Names["en"]
					region = record.Subdivisions[len(record.Subdivisions)-1].IsoCode
				}
				result.Location = IPLocation{
					Source:         mmDB.Metadata().DatabaseType,
					Continent:      record.Continent.Code,
					ContinentName:  record.Continent.Names["en"],
					Country:        record.Country.IsoCode,
					CountryName:    record.Country.Names["en"],
					Region:         region,
					RegionName:     regionName,
					City:           record.City.Names["en"],
					Latitude:       &record.Location.Latitude,
					Longitude:      &record.Location.Longitude,
					AccuracyRadius: &record.Location.AccuracyRadius,
				}
			} else {
				result.Location = IPLocation{
					Source: mmDB.Metadata().DatabaseType,
				}
			}

			result.Location.Timezone.Name = record.Location.TimeZone
			tz, err := time.LoadLocation(record.Location.TimeZone)
			if err == nil && len(record.Location.TimeZone) > 0 {
				_, offset := time.Now().In(tz).Zone()
				result.Location.Timezone.Offset = &offset
			}
		}
	}

	if mmDBASN != nil {
		record, err := mmDBASN.ASN(shortIP)
		if err != nil {
			log.Printf("MaxMind lookup for %v: %v", shortIP, err)
		} else {
			result.AS.Number = int(record.AutonomousSystemNumber)
			result.AS.Name = record.AutonomousSystemOrganization
		}
	}

	return
}

func handleMetrics(w http.ResponseWriter, r *http.Request, rConn *RecordingConn) {
	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)
	for _, cidr := range allowedMetrics {
		if cidr.Contains(remoteAddr.IP) {
			promhttpHandler.ServeHTTP(w, r)
			return
		}
	}

	hostRouter(w, r, rConn)
}

func healthz(w http.ResponseWriter, r *http.Request, rConn *RecordingConn) {
	w.Write([]byte("ok\n"))
}

func methodFilter(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead &&
			r.Method != http.MethodOptions {
			http.Error(w, "Method not allowed", http.StatusBadRequest)
			return
		}
		f(w, r)
	}
}

func fsWrap(f http.Handler) func(w http.ResponseWriter, req *http.Request, conn *RecordingConn) {
	return func(w http.ResponseWriter, req *http.Request, conn *RecordingConn) {
		f.ServeHTTP(w, req)
	}
}

func main() {
	flag.Parse()

	if *flagVersion {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			log.Panic("No buildinfo available")
		}
		fmt.Fprintf(os.Stderr, "https://%v version: %v\n", info.Main.Path, info.Main.Version)
		os.Exit(0)
	}

	reg := prometheus.DefaultRegisterer
	reg.MustRegister(prometheus.NewBuildInfoCollector())

	var err error
	mmDB, err = geoip2.Open(*flagMaxMindDB)
	if err != nil {
		if *flagMaxMindDB != "" {
			log.Printf("MaxMind DB error: %v", err)
		}
		mmDB = nil
	}

	mmDBASN, err = geoip2.Open(*flagMaxMindDBASN)
	if err != nil {
		if *flagMaxMindDBASN != "" {
			log.Printf("MaxMind DB error: %v", err)
		}
		mmDBASN = nil
	}

	for _, cidr := range strings.Split(*flagAllowedMetrics, ",") {
		if len(cidr) == 0 {
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("ParseCIDR: %q %v", cidr, err)
			continue
		}
		allowedMetrics = append(allowedMetrics, *n)
	}

	sandboxSelf()

	server := &http.Server{
		ConnContext:    ConnContext,
		MaxHeaderBytes: 1 << 15,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
	}

	http.HandleFunc("/metrics", connWrap(handleMetrics))
	http.HandleFunc("/healthz", connWrap(healthz))

	handler := func(path string, f http.HandlerFunc) {
		http.HandleFunc(path, methodFilter(promhttp.InstrumentHandlerCounter(
			httpRequests.MustCurryWith(prometheus.Labels{"handler": path}), f)))
	}

	http.Handle("/", gziphandler.GzipHandler(
		methodFilter(promhttp.InstrumentHandlerCounter(
			httpRequests.MustCurryWith(prometheus.Labels{"handler": "/"}),
			http.HandlerFunc(connWrap(hostRouter))))))
	handler("/cowsay", connWrap(cowsay))
	handler("/moo", connWrap(cowsay))
	handler("/about", connWrap(about))
	handler("/fun", connWrap(fun))
	handler("/fun/", connWrap(funThing))
	handler("/sh", connWrap(funThing))
	handler("/fun/reverse", connWrap(ip))

	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		log.Fatal(err)
	}
	handler("/.static/", connWrap(fsWrap(http.StripPrefix("/.static/", http.FileServer(http.FS(staticFS))))))

	go dnsServe()

	l, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}

	if *flagProxySupport {
		lr := &proxyproto.Listener{Listener: l}
		log.Fatal(server.Serve(RecordingListener{lr}))
	} else {
		log.Fatal(server.Serve(RecordingListener{l}))
	}
}

func extractSSL(header *proxyproto.Header) (*tlvparse.PP2SSL, error) {
	tlvs, err := header.TLVs()
	if err != nil {
		return nil, err
	}

	if ssl, ok := tlvparse.FindSSL(tlvs); ok {
		return &ssl, nil
	}

	// No SSL TLV, not an error.
	return nil, nil
}
