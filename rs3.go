package rs3

import (
	"rs3/database"
	"rs3/security"
	"rs3/server"
)

func ListenAndServe(domain, cert, key string) error {
	go serveHTTP(domain)
	serveHTTPS(domain, cert, key)
}
