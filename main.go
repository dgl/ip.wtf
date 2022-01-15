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
	flagMaxMindDBASN      = flag.String("maxmind-db-asn", "GeoLite2-ASN.mmdb", "MaxMind IP database for ASN")
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
	} else {
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

type GeoIPInfo struct{ Country string }
type ASNInfo struct { ASN interface{} }

func ip(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)

	w.Header().Add("X-Super-Cow-Powers", "curl "+*flagHost+"/moo")

	t := resolveAccept(req)
	if t == Plain {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		w.Write([]byte(remoteAddr.IP.String() + "\n"))
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

	geoIP := map[string]GeoIPInfo{}
	ASN := map[string]ASNInfo{}
	if mmDB != nil {
		if v4 := remoteAddr.IP.To4(); v4 != nil {
			record, err := mmDB.City(v4)
			if err != nil {
				log.Printf("MaxMind lookup for %v: %v", v4, err)
			} else {
				geoIP["IPv4"] = GeoIPInfo{record.Country.IsoCode}
			}
		} else {
			record, err := mmDB.Country(remoteAddr.IP)
			if err != nil {
				log.Printf("MaxMind lookup for %v: %v", remoteAddr.IP, err)
			} else {
				geoIP["IPv6"] = GeoIPInfo{record.Country.IsoCode}
			}
		}
	}

	if mmDBASN != nil {
		if v4 := remoteAddr.IP.To4(); v4 != nil {
			record, err := mmDB.ASN(v4)
			if err != nil {
				log.Printf("MaxMind lookup for %v: %v", v4, err)
			} else {
				ASN["IPv4"] = ASNInfo{record}
			}
		} else {
			record, err := mmDB.ASN(remoteAddr.IP)
			if err != nil {
				log.Printf("MaxMind lookup for %v: %v", remoteAddr.IP, err)
			} else {
				ASN["IPv6"] = ASNInfo{record}
			}
		}
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
		"IPv4":         remoteAddr.IP.To4(),
		"IPv6":         remoteAddr.IP,
		"GeoIP":        geoIP,
		"RemoteAddr":   remoteAddr,
		"RequestCount": rConn.read.count,
		"Request":      string(rConn.read.read),
		"Host":         *flagHost,
		"V4Host":       *flagV4Host,
		"V6Host":       *flagV6Host,
		"DNSHost":      ".dns." + *flagHost,
		"DNSID":        dnsID.String(),
	})

	if err != nil {
		log.Printf("templating failed: %v", err)
		http.Error(w, "Failed rendering template", http.StatusInternalServerError)
	}
}

func geoIP(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	p := strings.SplitN(req.URL.Path, "/", 3)
	if len(p) != 3 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(p[2])
	if ip == nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	record, err := mmDB.Country(ip)
	if err != nil {
		log.Printf("MaxMind lookup for %v: %v", ip, err)
	} else {
		err := json.NewEncoder(w).Encode(
			GeoIPInfo{record.Country.IsoCode})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
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
		ConnContext: ConnContext,
	}

	handler := func(path string, f http.HandlerFunc) {
		http.HandleFunc(path, methodFilter(promhttp.InstrumentHandlerCounter(
			httpRequests.MustCurryWith(prometheus.Labels{"handler": path}), f)))
	}

	handler("/", connWrap(hostRouter))
	handler("/cowsay", connWrap(cowsay))
	handler("/moo", connWrap(cowsay))
	handler("/.geoip/", connWrap(geoIP))

	http.HandleFunc("/metrics", connWrap(handleMetrics))

	l, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}
	go dnsServe()
	log.Fatal(server.Serve(RecordingListener{l}))
}
