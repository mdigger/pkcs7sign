package pkcs7

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// LoadCertificate load & parses a single certificate from the given ASN.1 DER file (*.cer).
func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(data)
}

func LoadPKCS1PrivateKeyPEM(path, password string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("Invalid key; no PEM data found")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Invalid key; no RSA PRIVATE KEY block")
	}
	data, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		if err != x509.IncorrectPasswordError {
			return nil, err
		}
		data = block.Bytes
	}
	return x509.ParsePKCS1PrivateKey(data)
}
