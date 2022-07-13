package pkcs7

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

func LoadCertificate(reader io.Reader) (cert *x509.Certificate, err error) {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return LoadCertificateFromBytes(data)
}

func LoadCertificateFromFile(path string) (cert *x509.Certificate, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return LoadCertificate(file)
}

func LoadCertificateFromBytes(data []byte) (cert *x509.Certificate, err error) {
	return x509.ParseCertificate(data)
}

func LoadPKCS1PrivateKeyPEM(reader io.Reader, password string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return LoadPKCS1PrivateKeyPEMFromBytes(bytes, password)
}

func LoadPKCS1PrivateKeyPEMFromBytes(data []byte, password string) (c *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("Invalid key; no PEM data found")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Invalid key; no RSA PRIVATE KEY block")
	}
	var cert []byte
	if !x509.IsEncryptedPEMBlock(block) {
		cert = block.Bytes
	} else if cert, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(cert)
}

func LoadPKCS1PrivateKeyPEMFromFile(path, password string) (*rsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return LoadPKCS1PrivateKeyPEM(file, password)
}
