package main

import (
	"context"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
)

var (
	flagListen = flag.String("listen", ":8080", "[ip]:port to listen for HTTP connections on")
	flagV4Host = flag.String("v4-host", "127.0.0.1:8080", "Host for IPv4 access")
	flagV6Host = flag.String("v6-host", "[::1]:8080", "Host for IPv6 access")
)

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
	read []byte
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
	ACCEPT: for _, accept := range accepts {
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

func ip(w http.ResponseWriter, req *http.Request) {
	v := req.Context().Value(ConnContextKey)
	rConn := v.(RecordingConn)

	t := resolveAccept(req)
	if t == Plain {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")
		w.Write([]byte(rConn.RemoteAddr().(*net.TCPAddr).IP.String()))
		return
	}

	rConn.read.count += 1

	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)

	err := ipTmpl.Execute(w, map[string]interface{}{
		"IPv4": remoteAddr.IP.To4(),
		"IPv6": remoteAddr.IP,
		"RemoteAddr": remoteAddr,
		"RequestCount": rConn.read.count,
		"Request": string(rConn.read.read),
		"V4Host": *flagV4Host,
		"V6Host": *flagV6Host,
	})

	if err != nil {
		log.Printf("templating failed: %v", err)
		http.Error(w, "Failed rendering template", http.StatusInternalServerError)
	}
	rConn.read.read = nil
}

func main() {
	flag.Parse()

	server := &http.Server{
		ConnContext: ConnContext,
	}
	http.HandleFunc("/", ip)
	l, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Serve(RecordingListener{l}))
}
