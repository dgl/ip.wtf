package main

import (
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

var (
	flagListen    = flag.String("listen", ":8080", "[ip]:port to listen for HTTP connections on")
	flagHost      = flag.String("host", "ip.d.cx", "Hostname for the overall application")
	flagV4Host    = flag.String("v4-host", "127.0.0.1:8080", "Host for IPv4 access")
	flagV6Host    = flag.String("v6-host", "[::1]:8080", "Host for IPv6 access")
	flagMaxMindDB = flag.String("maxmind-db", "GeoLite2-Country.mmdb", "MaxMind IP database")
)

var mmDB *geoip2.Reader

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
		switch i := strings.Split(accept, ";"); i[0] {
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
	} else {
		ip(w, req, conn)
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

func ip(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	t := resolveAccept(req)
	if t == Plain {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		w.Write([]byte(rConn.RemoteAddr().(*net.TCPAddr).IP.String()))
		return
	}

	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)

	geoIP := map[string]GeoIPInfo{}
	if mmDB != nil {
		if v4 := remoteAddr.IP.To4(); v4 != nil {
			record, err := mmDB.Country(v4)
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

	err := ipTmpl.Execute(w, map[string]interface{}{
		"IPv4":         remoteAddr.IP.To4(),
		"IPv6":         remoteAddr.IP,
		"GeoIP":        geoIP,
		"RemoteAddr":   remoteAddr,
		"RequestCount": rConn.read.count,
		"Request":      string(rConn.read.read),
		"Host":         *flagHost,
		"V4Host":       *flagV4Host,
		"V6Host":       *flagV6Host,
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

	server := &http.Server{
		ConnContext: ConnContext,
	}
	http.HandleFunc("/", connWrap(hostRouter))
	http.HandleFunc("/.geoip/", connWrap(geoIP))
	l, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}
	go dnsServe()
	log.Fatal(server.Serve(RecordingListener{l}))
}
