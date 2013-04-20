package rs3

import (
	"errors"
	"fmt"
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
		database.Restore(c.BackupPath)
	}

	defer func() {
		err := recover()
		fmt.Printf("*** TYPE ***: %T\n", err)
		if err != nil {
			fmt.Println(err)
		}
		database.Backup(c.BackupPath)
	}()

	go database.Console()
	go server.ServeHTTP(c.Domain)
	server.ServeHTTPS(c.Domain, c.CertPath, c.KeyPath)
	return nil
}
