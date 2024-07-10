package clone

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func SignCert(cert, parent *x509.Certificate, caPrivKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	pubKey := parent.PublicKey.(*rsa.PublicKey)

	privKey, err := rsa.GenerateKey(rand.Reader, pubKey.N.BitLen())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	if caPrivKey == nil {
		caPrivKey = privKey
		parent.PublicKey = nil
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	newCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse certificate: %w", err)
	}

	return newCert, privKey, nil
}

func SaveCert(prefix string, cert *x509.Certificate, privKey *rsa.PrivateKey) error {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return fmt.Errorf("cannot PEM encode certificate: %w", err)
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	if err != nil {
		return fmt.Errorf("cannot PEM encode private key: %w", err)
	}

	if err = os.WriteFile(prefix+".pem", certPEM.Bytes(), 0644); err != nil {
		return fmt.Errorf("cannot create PEM file: %w", err)
	}

	if err = os.WriteFile(prefix+".key", certPrivKeyPEM.Bytes(), 0644); err != nil {
		return fmt.Errorf("cannot create KEY file: %w", err)
	}

	return nil
}
