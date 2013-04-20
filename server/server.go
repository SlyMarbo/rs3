package server

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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
	switch {
	case r.URL.Path == "/", r.URL.Path == "/index.html":
		ServeMain(w, r)
		
	case r.URL.Path == "/login":
		Login(w, r)
		
	case strings.HasSuffix(r.URL.Path, "favicon.ico"):
		http.ServeFile(w, r, "server/content/images/favicon.ico")
		
	case strings.HasPrefix(r.URL.Path, "/css/"),
		strings.HasPrefix(r.URL.Path, "/js/"),
		strings.HasPrefix(r.URL.Path, "/images/"):
		http.ServeFile(w, r, "server/content" + r.URL.Path)
		
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
