package server

import (
	"fmt"
	"io"
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
		
	case strings.HasPrefix(r.URL.Path, "/css/"):
		serveCSS(w, r, "server/content" + r.URL.Path)
		
	case strings.HasPrefix(r.URL.Path, "/js/"):
		serveJS(w, r, "server/content" + r.URL.Path)
		
	case strings.HasPrefix(r.URL.Path, "/images/"):
		serveImage(w, r, "server/content" + r.URL.Path)
		
	default:
		NotFound(w, r)
	}
}


func ServeHTTPS(domain, cert, key string) {
	err := http.ListenAndServeTLS(domain + ":443", cert, key, Nexus{})
	if err != nil {
		log.Panic(err)
	}
}

func serveCSS(w http.ResponseWriter, r *http.Request, s string) {
	cache := database.Gzip(s)
	
	file, err := os.Open(s)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Add("Content-Type", "text/css; charset=utf-8")
	w.Header().Add("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	_, err = io.Copy(w, file)
	if err != nil {
		log.Println("Failed to send", s)
		log.Println(err)
		return
	}
}

func serveJS(w http.ResponseWriter, r *http.Request, s string) {
	file, err := os.Open(s)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Add("Content-Type", "application/x-javascript; charset=utf-8")
	w.Header().Add("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	_, err = io.Copy(w, file)
	if err != nil {
		log.Println("Failed to send", s)
		log.Println(err)
		return
	}
}

func serveImage(w http.ResponseWriter, r *http.Request, s string) {
	file, err := os.Open(s)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Add("Content-Type", "image/png")
	w.Header().Add("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	_, err = io.Copy(w, file)
	if err != nil {
		log.Println("Failed to send", s)
		log.Println(err)
		return
	}
}
