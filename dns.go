package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
)

const SOA string = "@ SOA ip.d.cx. ip.d.cx. 2021010100 1800 900 0604800 60"

// NewRR is a shortcut to dns.NewRR that ignores the error.
func NewRR(s string) dns.RR { r, _ := dns.NewRR(s); return r }

func main() {
    z := "ns.ip.d.cx"
    
    rrx := NewRR("$ORIGIN " + z + ".\n" + SOA)
	dns.HandleFunc(z, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Ns = []dns.RR{rrx}
		w.WriteMsg(m)
	})

	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "tcp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set tcp listener %s\n", err.Error())
		}
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}