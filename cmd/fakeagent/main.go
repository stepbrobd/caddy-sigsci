// fakeagent runs the fake module RPC listener next to a plain http echo
// upstream (for testing only)

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/stepbrobd/caddy-sigsci/internal/fakeagent"
)

func main() {
	network := flag.String("network", "tcp", "RPC listener network")
	address := flag.String("address", "127.0.0.1:9999", "RPC listener address")
	echo := flag.String("echo", "127.0.0.1:8081", "HTTP echo upstream address")
	flag.Parse()

	ln, err := net.Listen(*network, *address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("rpc listening on %s %s", *network, *address)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "echo %s %s agentresponse=%q requestid=%q tags=%q body=%q\n", r.Method, r.URL.Path,
				r.Header.Get("X-Sigsci-Agentresponse"), r.Header.Get("X-Sigsci-Requestid"), r.Header.Get("X-Sigsci-Tags"), body)
		})
		log.Printf("echo upstream on %s", *echo)
		log.Fatal(http.ListenAndServe(*echo, mux))
	}()

	log.Fatal(fakeagent.Serve(ln, fakeagent.Agent{}))
}
