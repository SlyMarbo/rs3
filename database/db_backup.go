package database

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

func Backup(path string) error {
	handle := func(err error) {
		if err != nil {
			panic(new(BackupFailure).Append(err))
		}
	}

	// Gzip database JSON into buffer.
	compressed := new(bytes.Buffer)
	zipper := gzip.NewWriter(compressed)
	_, err := io.Copy(zipper, Reader())
	handle(err)
	zipper.Close()
	
	myBuf := new(bytes.Buffer)
	_, err = io.Copy(myBuf, Reader())
	handle(err)
	err = ioutil.WriteFile("database/backup.json", myBuf.Bytes(), 0644)
	handle(err)

	// Prepare crypto.
	var key, iv []byte
	_, err = os.Stat("database/backup.key")
	
	// If we don't have an existing key.
	if os.IsNotExist(err) {
		
		// Create a key.
		key = make([]byte, 32) //256 bits
		_, err := io.ReadFull(rand.Reader, key)
		handle(err)
		
		// Create an initialisation vector.
		iv = make([]byte, aes.BlockSize)
		_, err = io.ReadFull(rand.Reader, iv)
		handle(err)
		
		// Write key.
		err = ioutil.WriteFile("database/backup.key", key, 0644)
		handle(err)
		
		// Write IV.
		err = ioutil.WriteFile("database/backup_iv.key", iv, 0644)
		handle(err)
		
	} else {
		
		// Read in key.
		key = make([]byte, 32)
		key, err = ioutil.ReadFile("database/backup.key")
		handle(err)
		
		// Read in IV.
		iv = make([]byte, aes.BlockSize)
		iv, err = ioutil.ReadFile("database/backup_iv.key")
		handle(err)
	}
	
	// Create the encrypter.
	block, err := aes.NewCipher(key)
	handle(err)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	handle(err)
	
	// Add padding if necessary.
	dif := aes.BlockSize - (compressed.Len() % aes.BlockSize)
	if dif == 0 {
		dif = aes.BlockSize
	}
	for i := 0; i < dif; i++ {
		compressed.Write([]byte{byte(dif)})
	}
	
	// Encrypt the data.
	data := compressed.Bytes()
	encrypter.CryptBlocks(data, data)
	
	// Write to disk.
	err = ioutil.WriteFile(path, data, 0644)
	handle(err)
	
	
	return nil
}








func Restore(path string) error {
	handle := func(err error) {
		if err != nil {
			panic(new(RestoreFailure).Append(err))
		}
	}
	
	// Read in key.
	key, err := ioutil.ReadFile("database/backup.key")
	handle(err)
	iv, err := ioutil.ReadFile("database/backup_iv.key")
	handle(err)
	
	// Create decrypter.
	block, err := aes.NewCipher(key)
	handle(err)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	
	// Read in backup.
	data, err := ioutil.ReadFile(path)
	handle(err)
	
	// Decrypt.
	decrypter.CryptBlocks(data, data)

	// Remove padding.
	dif := int(data[len(data)-1])
	data = data[:len(data)-dif]

	// Unzip.
	r := bytes.NewBuffer(data)
	unzipper, err := gzip.NewReader(r)
	handle(err)
	// unzipper.Close()
	_, err = io.Copy(new(Database), unzipper)
	//jsone, err := ioutil.ReadAll(unzipper)
	handle(err)
	unzipper.Close()

	return nil
}

type BackupFailure struct{}

func (b BackupFailure) Append(err error) error {
	return errors.New(b.Error() + ": " + err.Error())
}

func (err BackupFailure) Error() string {
	return "Failed to Backup Database"
}

type RestoreFailure struct{}

func (r RestoreFailure) Append(err error) error {
	return errors.New(r.Error() + ": " + err.Error())
}

func (err RestoreFailure) Error() string {
	return "Failed to Restore Database"
}
