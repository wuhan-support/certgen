package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/wuhan-support/certgen/keys"
	"golang.org/x/crypto/openpgp"
	"os"
	"strings"
)

func GenerateCertID(record Record) string {
	message := fmt.Sprintf("[%s] %s <%s>", record.Group, record.Name, record.Email)
	hash := sha512.Sum512([]byte(message))
	return hex.EncodeToString(hash[:])
}

func GenerateSignMessage(record Record) string {
	return fmt.Sprintf("兹证明：%s 于 wuhan.support %s 做出其贡献", record.Name, record.Group)
}

// PGPSignString sign message and returns an ASCII-armored signed message
func PGPSignString(message string) string {
	// Read in public key
	keyringFileBuffer, _ := os.Open(keys.SecretKey)
	defer keyringFileBuffer.Close()

	entityList, err := openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		panic(err)
	}

	entity := entityList[0]

	err = entity.PrivateKey.Decrypt(keys.SecretKeyPassphrase)
	if err != nil {
		panic(err)
	}

	writeBuf := new(bytes.Buffer)
	readBuf := strings.NewReader(message)
	err = openpgp.ArmoredDetachSign(writeBuf, entity, readBuf, nil)
	if err != nil {
		panic(err)
	}

	return writeBuf.String()
}

func sanitize(message string) string {
	m := strings.TrimSpace(message)
	return strings.ReplaceAll(m, "\uFEFF", "")
}
