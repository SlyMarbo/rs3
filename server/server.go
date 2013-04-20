package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type HTTPRedirector struct{}

func (_ HTTPRedirector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := r.URL
	url.Scheme = "https"
	http.Redirect(w, r, url.String(), 301)
}

func ServeHTTP(domain string) {
	for {
		err := http.ListenAndServe(domain, HTTPRedirector{})
		fmt.Fprintf(os.Stderr, err.Error())
		time.Sleep(10 * time.Second)
	}
}


type Nexus struct{}

func (_ Nexus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		ServeMain(w, r)
		
	case "/login":
		ServeLogin(w, r)
		
	default:
		NotFound(w, r)
	}
}


func ServeHTTPS(domain, cert, key string) {
	err := http.ListenAndServeTLS(domain, cert, key, Nexus{})
	if err != nil {
		log.Fatal(err)
	}
}
