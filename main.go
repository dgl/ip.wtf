package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"flag"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/oschwald/geoip2-golang"
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
	flagAllowedMetrics = flag.String("allowed-metrics", "127.0.0.0/8,192.168.0.0/16,10.0.0.0/8,::1/128", "IPs allowed to fetch metrics")
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

var ipTmpl = template.Must(template.ParseFiles("ip.html"))

type RecordingListener struct {
	net.Listener
}

func (l RecordingListener) Accept() (net.Conn, error) {
	rw, err := l.Listener.Accept()
	return RecordingConn{Conn: rw, read: &readInfo{}}, err
}

type RecordingConn struct {
	net.Conn
	read *readInfo
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
	if strings.Contains(ua, "curl/") || strings.Contains(ua, "Wget/") {
		return Plain
	}
	if mode := req.Header.Get("Sec-Fetch-Mode"); mode == "cors" {
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
		ipDetails(w, req, conn)
	} else {
		log.Printf("Not found: %q", req.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
	}
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

	w.Header().Add("X-Super-Cow-Powers", "curl "+*flagHost+"/moo")

	switch resolveAccept(req) {
	case Plain:
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		w.Write([]byte(remoteAddr.IP.String() + "\n"))
		return
	case Json:
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		req.URL.Path = "/" + remoteAddr.IP.String()
		ipDetails(w, req, rConn)
		return
	}

	if req.Host == "ip.d.cx" {
		http.Redirect(w, req, "http://"+*flagHost, http.StatusMovedPermanently)
		return
	} else if req.Host == "v4.ip.d.cx" {
		http.Redirect(w, req, "http://v4."+*flagHost, http.StatusMovedPermanently)
		return
	} else if req.Host == "v6.ip.d.cx" {
		http.Redirect(w, req, "http://v6."+*flagHost, http.StatusMovedPermanently)
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

	err = ipTmpl.Execute(w, map[string]interface{}{
		"IPv4":       remoteAddr.IP.To4(),
		"IPv6":       remoteAddr.IP,
		"RemoteAddr": remoteAddr,
		"Details": map[string]interface{}{
			remoteAddr.IP.String(): lookupIP(remoteAddr.IP),
		},
		"RequestCount": rConn.read.count,
		"Request":      string(rConn.read.read),
		"Host":         *flagHost,
		"V4Host":       *flagV4Host,
		"V6Host":       *flagV6Host,
		"DNSHost":      ".dns." + *flagHost,
		"DNSID":        dnsID.String(),
		"Spider":       req.Header.Get("From") != "",
	})

	if err != nil {
		log.Printf("templating failed: %v", err)
		http.Error(w, "Failed rendering template", http.StatusInternalServerError)
	}
}

func ipDetails(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	ip := net.ParseIP(req.URL.Path[1:])
	if ip == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(lookupIP(ip))
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
			result.Location.Continent = record.Continent.Code
			result.Location.ContinentName = record.Continent.Names["en"]

			result.Location.Country = record.Country.IsoCode
			result.Location.CountryName = record.Country.Names["en"]

			result.Location.City = record.City.Names["en"]

			result.Location.Latitude = record.Location.Latitude
			result.Location.Longitude = record.Location.Longitude

			result.Location.Timezone.Name = record.Location.TimeZone
			// TODO: add offset

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

func methodFilter(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" && r.Method != "HEAD" &&
			r.Method != "OPTIONS" {
			http.Error(w, "Method not allowed", http.StatusBadRequest)
			return
		}
		f(w, r)
	}
}

func main() {
	flag.Parse()

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

	server := &http.Server{
		ConnContext:    ConnContext,
		MaxHeaderBytes: 1 << 15,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
	}

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

	http.HandleFunc("/metrics", connWrap(handleMetrics))

	l, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}
	go dnsServe()
	log.Fatal(server.Serve(RecordingListener{l}))
}
