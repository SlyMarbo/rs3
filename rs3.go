package rs3

import (
	"errors"
	"fmt"
	"log"
	"rs3/database"
	"rs3/server"
)

type Config struct {
	Domain     string
	CertPath   string
	KeyPath    string
	BackupPath string
}

func (c *Config) ListenAndServe() error {
	if c.Domain == "" {
		return errors.New("Error: domain name not given.")
	} else if c.CertPath == "" {
		return errors.New("Error: certificate path not given.")
	} else if c.KeyPath == "" {
		return errors.New("Error: key path not given.")
	}

	if c.BackupPath != "" {
		err := database.Restore(c.BackupPath)
		if err != nil {
			log.Panic(err)
		}
	}

	defer func() {
		err := recover()
		if s, ok := err.(string); err != nil && (!ok || s == "") {
			fmt.Println(err)
		}
		err = database.Backup(c.BackupPath)
		if err != nil {
			log.Panic(err)
		}
	}()

	go server.ServeHTTP(c.Domain)
	go server.ServeHTTPS(c.Domain, c.CertPath, c.KeyPath)
	database.Console()
	return nil
}
