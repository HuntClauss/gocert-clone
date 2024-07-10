package clone

import (
	"crypto/tls"
	"fmt"
)

func Visit(link string) error {
	conn, err := tls.Dial("tcp", link, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("cannot tcp dial: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	cert := certs[len(certs)-1]
	cert, privKey, err := SignCert(cert, cert, nil)
	if err != nil {
		return fmt.Errorf("cannot sign certificate: %w", err)
	}

	if err = SaveCert(fmt.Sprintf("./certs/%s-%d-%s", cert.Subject.CommonName, len(certs), link), cert, privKey); err != nil {
		return fmt.Errorf("cannot save certificate: %w", err)
	}

	for i := len(certs) - 2; i >= 0; i-- {
		cert, privKey, err = SignCert(certs[i], cert, privKey)
		if err != nil {
			return fmt.Errorf("cannot sign certificate: %w", err)
		}

		if err = SaveCert(fmt.Sprintf("./certs/%s-%d-%s", cert.Subject.CommonName, i+1, link), cert, privKey); err != nil {
			return fmt.Errorf("cannot save certificate: %w", err)
		}
	}

	return nil
}
