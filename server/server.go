package server

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

type HTTPRedirector struct {}

func (_ HTTPRedirector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := r.URL
	url.Scheme = "https"
	http.Redirect(w, r, url.String(), 301)
}

func serveHTTP(domain string) {
	for {
		err := http.ListenAndServe(domain, HTTPRedirector{})
		fmt.Fprintf(os.Stderr, err.Error())
		time.Sleep(10 * time.Second)
	}
}


func serveHTTPS(domain, cert, key string) {
	
}
