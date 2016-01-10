package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"time"
)

var (
	oidPKCS1RSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPKCS7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidPKCS9ContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidPKCS9MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidPKCS9SigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA1               = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

func Sign(data io.Reader, cert *x509.Certificate, priv *rsa.PrivateKey) ([]byte, error) {
	// вычисляем хеш от данных
	var hash = sha1.New()
	if _, err := io.Copy(hash, data); err != nil {
		return nil, err
	}
	// инициализируем данные подписи
	var signedData = signedData{
		Version: 1,
		DigestAlgorithms: []algorithmIdentifier{{
			Algorithm:  oidSHA1,
			Parameters: asn1.RawValue{Tag: 5},
		}},
		ContentInfo: contentInfo{Type: oidPKCS7Data},
		Certificates: asn1.RawValue{ // плюс добавляем корневой сертификат Apple
			Class: 2, Tag: 0, Bytes: append(wwdr, cert.Raw...), IsCompound: true,
		},
		SignerInfos: []signerInfo{{
			Version: 1,
			IssuerAndSerialNumber: issuerAndSerialNumber{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
			DigestAlgorithm: algorithmIdentifier{
				Algorithm:  oidSHA1,
				Parameters: asn1.RawValue{Tag: 5},
			},
			AuthenticatedAttributes: []attribute{
				newAttribute(oidPKCS9ContentType, oidPKCS7Data),
				newAttribute(oidPKCS9SigningTime, time.Now().UTC()), // время подписи
				newAttribute(oidPKCS9MessageDigest, hash.Sum(nil)),  // хеш данных
			},
			DigestEncryptionAlgorithm: algorithmIdentifier{
				Algorithm:  oidPKCS1RSAEncryption,
				Parameters: asn1.RawValue{Tag: 5},
			},
		}},
	}
	// кодируем атрибуты
	encodedAuthenticatedAttributes, err := asn1.Marshal(
		signedData.SignerInfos[0].AuthenticatedAttributes)
	if err != nil {
		return nil, err
	}
	// For the digest of the authenticated attributes, we need a
	// slightly different encoding.  Change the attributes from a
	// SEQUENCE to a SET.
	var originalFirstByte = encodedAuthenticatedAttributes[0]
	encodedAuthenticatedAttributes[0] = 0x31
	hash = sha1.New()
	hash.Write(encodedAuthenticatedAttributes)
	var attributesDigest = hash.Sum(nil)
	encodedAuthenticatedAttributes[0] = originalFirstByte
	// подписываем атрибуты
	encryptedDigest, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, attributesDigest)
	if err != nil {
		return nil, err
	}
	// добавляем сигнатуру подписанных атрибутов
	signedData.SignerInfos[0].EncryptedDigest = encryptedDigest
	// инициализируем контейнер с данными подписи и возвращаем его уже в виде байтов
	return asn1.Marshal(container{
		OID:        oidPKCS7SignedData,
		SignedData: signedData,
	})
}

type container struct {
	OID        asn1.ObjectIdentifier
	SignedData signedData `asn1:"tag:0,explicit,optional"`
}

// signedData is defined in rfc2315, section 9.1.
type signedData struct {
	Version          int                   `asn:"default:1"`
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	CRLS             asn1.RawValue `asn1:"tag:1,optional"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type contentInfo struct {
	Type asn1.ObjectIdentifier
	// Content is optional in PKCS#7 and not provided here.
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"tag:0,optional"`
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"tag:1,optional"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue // pkix.RDNSequence // pkix.Name
	SerialNumber *big.Int
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []interface{} `asn1:"set"`
}

func newAttribute(typ asn1.ObjectIdentifier, val interface{}) attribute {
	if t, ok := val.(time.Time); ok {
		val = asn1.RawValue{Tag: 23, Bytes: []byte(t.Format("060102150405Z"))}
	}
	return attribute{Type: typ, Values: []interface{}{val}}
}
