package rs3

import (
	"rs3/server"
)

func ListenAndServe(domain, cert, key string) error {
	go server.ServeHTTP(domain)
	server.ServeHTTPS(domain, cert, key)
	return nil
}
