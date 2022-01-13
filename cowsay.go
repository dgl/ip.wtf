package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	basicCow = `        o   ^__^
         o  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
`
	ipCow = `        \   ^__^
         \  (oo)\_______            ip.wtf
            (__)\       )\/\
                ||----w |
                ||     ||
`
	ipBCow = `                      ^__^   /
ip.wtf        _______/(oo)  /
          \/\(       /(__)
             | w----||
             ||     ||
`
)

func cowsay(w http.ResponseWriter, req *http.Request, rConn *RecordingConn) {
	if !strings.Contains(req.Header.Get("User-Agent"), "curl/") {
		w.Write([]byte("<b><a href=/>ip.wtf!</a></b><br><br>To see the super cow powers, please run: <code>curl ip.wtf/moo</code>"))
	} else {
		remoteAddr := rConn.RemoteAddr().(*net.TCPAddr)
		w.Write([]byte("\x1bc"))
		w.Write([]byte(cowsayText(0, "What the fuck is my IP address?", basicCow, "")))
		if w, ok := w.(http.Flusher); ok {
			w.Flush()
		}
		time.Sleep(950 * time.Millisecond)
		w.Write([]byte("\x1bc"))
		v4 := remoteAddr.IP.To4()
		ip := remoteAddr.IP.String()
		proto := "v6"
		if v4 != nil {
			ip = v4.String()
			proto = "v4"
		}
		if rand.Intn(3) > 1 {
			w.Write([]byte(cowsayText(0, fmt.Sprintf("It's fucking %v", ip), ipCow, proto)))
		} else {
			w.Write([]byte(cowsayText(50, fmt.Sprintf("It's fucking %v", ip), ipBCow, proto)))
		}
		if rand.Intn(4) > 2 {
			// iTerm2 special, shame we can't work out what terminal is on the other end...
			w.Write([]byte("\x1b]1337;RequestAttention=fireworks\a\r"))
		}
	}
}

func cowsayText(align int, text, template, proto string) string {
	var o strings.Builder
	// VTE / iTerm2 URL escape.
	template = strings.Replace(template, "ip.wtf", "\x1b]8;;http://ip.wtf\aip.wtf\x1b]8;;\a", 1)
	template = strings.Replace(template, "xx", proto, 1)
	n := align-4-len(text)
	if n > 0 {
		for i := 0; i < n; i++ {
			o.WriteRune(' ')
		}
	}
	o.WriteRune(' ')
	o.WriteString(strings.Repeat("_", len(text)+2))
	o.WriteRune('\n')

	if n > 0 {
		for i := 0; i < n; i++ {
			o.WriteRune(' ')
		}
	}
	o.WriteString("< ")
	o.WriteString(text)
	o.WriteString(" >")
	o.WriteRune('\n')

	if n > 0 {
		for i := 0; i < n; i++ {
			o.WriteRune(' ')
		}
	}
	o.WriteRune(' ')
	o.WriteString(strings.Repeat("-", len(text)+2))
	o.WriteRune('\n')

	o.WriteString(template)

	return o.String()
}
