package pkcs7

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"
)

func loadWWDR(name string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(b)
}

func TestSign(t *testing.T) {
	wwdr, err := loadWWDR("AppleWWDRCA.cer")
	if err != nil {
		t.Fatal("Error loading WWDR certificate:", err)
	}
	cert, err := LoadCertificate("cert.cer")
	if err != nil {
		t.Fatal("Error loading certificate:", err)
	}
	priv, err := LoadPKCS1PrivateKeyPEM("key.pem", "test")
	if err != nil {
		t.Fatal("Error loading private certificate:", err)
	}
	f, err := os.Open("manifest.json")
	if err != nil {
		t.Fatal("Error opening manifest:", err)
	}
	defer f.Close()
	data, err := Sign(f, cert, priv, wwdr)
	if err != nil {
		t.Fatal("Error signing manifest:", err)
	}
	if err := ioutil.WriteFile("signature-test", data, 0666); err != nil {
		t.Fatal("Error writing signature:", err)
	}
}
