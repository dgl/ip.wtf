package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

var pageTmpl = template.Must(template.ParseFS(content, "page.html"))

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

	f, err := content.Open(page)
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

	params := map[string]interface{}{
		"IPv4":       remoteAddr.IP.To4(),
		"IPv6":       remoteAddr.IP,
		"RemoteAddr": remoteAddr,
		"Request":    req,
		"Devel":      len(*flagLocation) == 0,
	}

	mdBuf := strings.Builder{}
	mdTmpl, err := template.New(page).Parse(buf.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := mdTmpl.Execute(&mdBuf, params); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	params["Content"] = template.HTML(mdBuf.String())

	if err := pageTmpl.Execute(w, params); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func funThing(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	s := strings.Split(req.URL.Path, "/")
	if len(s) < 2 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	page := s[len(s)-1]

	for _, r := range page {
		if r < 'a' || r > 'z' {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
	}

	name := fmt.Sprintf("fun/%s.html", page)
	f, err := content.Open(name)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	fi, _ := f.Stat()
	ff, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	http.ServeContent(w, req, name, fi.ModTime(), ff)
}
