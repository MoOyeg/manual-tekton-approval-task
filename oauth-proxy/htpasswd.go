package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// Lookup passwords in a htpasswd file
// Passwords must be generated with -B for bcrypt or -s for SHA1.

type HtpasswdFile struct {
	Users map[string]string
}

func NewHtpasswdFromFile(path string) (*HtpasswdFile, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return NewHtpasswd(r)
}

func NewHtpasswd(file io.Reader) (*HtpasswdFile, error) {
	csv_reader := csv.NewReader(file)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		return nil, err
	}
	h := &HtpasswdFile{Users: make(map[string]string)}
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
	return h, nil
}

func (h *HtpasswdFile) Validate(user string, password string) bool {
	realPassword, exists := h.Users[user]
	if !exists {
		return false
	}
	shaPrefix := realPassword[:5]
	if shaPrefix == "{SHA}" {
		shaValue := realPassword[5:]
		d := sha1.New()
		d.Write([]byte(password))
		return shaValue == base64.StdEncoding.EncodeToString(d.Sum(nil))
	}

	bcryptPrefix := realPassword[:4]
	if bcryptPrefix == "$2a$" || bcryptPrefix == "$2x$" || bcryptPrefix == "$2y$" {
		return bcrypt.CompareHashAndPassword([]byte(realPassword), []byte(password)) == nil
	}

	log.Printf("Invalid htpasswd entry for %s. Must be a SHA or bcrypt entry.", user)
	return false
}
