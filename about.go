package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

var pageTmpl = template.Must(template.ParseFiles("page.html"))

func about(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	renderPage("about.md", w, req, rConn)
}

func fun(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	renderPage("fun/index.md", w, req, rConn)
}

func renderPage(page string, w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)

	w.Header().Add("X-Super-Cow-Powers", "curl "+*flagHost+"/moo")
	w.Header().Add("Cache-Control", "no-store")

	f, err := os.Open(page)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	var buf bytes.Buffer
	source, _ := io.ReadAll(f)
	md := goldmark.New(
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithUnsafe(),
		))
	if err := md.Convert(source, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := pageTmpl.Execute(w, map[string]interface{}{
		"Content":    template.HTML(buf.String()),
		"IPv4":       remoteAddr.IP.To4(),
		"IPv6":       remoteAddr.IP,
		"RemoteAddr": remoteAddr,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func funThing(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	s := strings.SplitN(req.URL.Path, "/", 3)
	if len(s) != 3 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Go validates Path but we'll make sure it's just simple characters as we
	// directly serve it here.
	for _, r := range s[2] {
		if r < 'a' || r > 'z' {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
	}

	http.ServeFile(w, req, fmt.Sprintf("fun/%s.html", s[2]))
}
