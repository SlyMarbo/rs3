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
	url.Host = r.Host
	fmt.Println(url.String())
	http.Redirect(w, r, url.String(), 301)
}

func ServeHTTP(domain string) {
	for {
		err := http.ListenAndServe(domain + ":80", HTTPRedirector{})
		fmt.Fprintf(os.Stderr, err.Error())
		time.Sleep(10 * time.Second)
	}
}


type Nexus struct{}

func (_ Nexus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	
	// Add HSTS.
	w.Header().Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	// Re-route request.
	switch r.URL.Path {
	case "/", "/index.html":
		ServeMain(w, r)
		
	case "/login":
		ServeLogin(w, r)
		
	case "/content/images/favicon.ico", "/favicon.ico":
		http.ServeFile(w, r, "server/content/images/favicon.ico")
		
	default:
		NotFound(w, r)
	}
}


func ServeHTTPS(domain, cert, key string) {
	err := http.ListenAndServeTLS(domain + ":443", cert, key, Nexus{})
	if err != nil {
		log.Fatal(err)
	}
}
