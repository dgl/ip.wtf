package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type DNSData struct {
	IP         string
	EdnsSubnet string
	Expire     time.Time
}

var (
	dnsListen = flag.String("dns-listen", ":8053", "Port to listen on for DNS server")
	dnsIP     = flag.String("dns-public-ip", "", "Public IP to return")
)

var (
	dnsMap   = map[string]DNSData{}
	dnsMapMu sync.RWMutex
)

func dnsHandler(w http.ResponseWriter, req *http.Request) {
	host := strings.TrimSuffix(req.Host, ".")

	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD")

	dnsMapMu.RLock()
	m, ok := dnsMap[host]
	dnsMapMu.RUnlock()

	if ok {
		err := json.NewEncoder(w).Encode(m)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// MustNewRR is a shortcut to dns.NewRR that panics on error.
func MustNewRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func dnsServe() {
	SOA := "@ SOA " + *flagHost + ". " + *flagHost + ". 2021010100 1800 900 0604800 60"
	myAddrA := ". 0 A " + *dnsIP

	z := "dns." + *flagHost
	rrx := MustNewRR("$ORIGIN " + z + ".\n" + SOA)
	dns.HandleFunc(z, func(w dns.ResponseWriter, r *dns.Msg) {
		subnet := ""
		for _, ext := range r.Extra {
			opt, ok := ext.(*dns.OPT)
			if !ok {
				continue
			}
			for _, s := range opt.Option {
				switch e := s.(type) {
				case *dns.EDNS0_SUBNET:
					subnet = e.String()
				}
			}
		}

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		if strings.ToLower(r.Question[0].Name) == z+"." {
			m.Answer = []dns.RR{rrx}
		} else {
			name := strings.TrimSuffix(r.Question[0].Name, ".")
			dnsMapMu.Lock()
			dnsMap[name] = DNSData{
				IP:         w.RemoteAddr().String(),
				EdnsSubnet: subnet,
				Expire:     time.Now().Add(2 * time.Minute),
			}
			dnsMapMu.Unlock()
			rr := MustNewRR(name + myAddrA)
			m.Answer = []dns.RR{rr}
		}
		w.WriteMsg(m)
	})

	if len(*dnsListen) == 0 {
		return
	}

	if len(*dnsIP) == 0 {
		return
	}

	// Periodically clean up expired DNS entries
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			dnsMapMu.Lock()
			for k, v := range dnsMap {
				if now.After(v.Expire) {
					delete(dnsMap, k)
				}
			}
			dnsMapMu.Unlock()
		}
	}()

	go func() {
		srv := &dns.Server{Addr: *dnsListen, Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	go func() {
		srv := &dns.Server{Addr: *dnsListen, Net: "tcp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set tcp listener %s\n", err.Error())
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
