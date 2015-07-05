// Ecca Authentication CA server
//
// Performs all client certificate signing duties.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

// Code to make all those keys, certificates and DNSSEC records.

package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "crypto/x509/pkix"
        "errors"
	"math/big"
        "time"
	"net"
)

// Generate 4k Root CA key.
func GenerateCA(subjectOrg string, subjectCN string, bits int) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{subjectOrg},
			CommonName: subjectCN,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: keyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),   // 5 years

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// parse to test ourselves.
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}

	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

// generate 3k FPCA key.
func GenerateFPCA(subjectOrg string, subjectCN string, caCert *x509.Certificate, caKey *rsa.PrivateKey, bits int) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	
	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{subjectOrg},
			CommonName: subjectCN,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(5, 0, 0).UTC(),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}

// create plain old https server certificates
// doesn't have to be too strong.
func GenerateCert(serverName string, altnames []string, caCert *x509.Certificate, caKey *rsa.PrivateKey, bits int) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	serial := randBigInt()
	keyId := randBytes()

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: serverName,
		},

		SerialNumber:   serial,
		SubjectKeyId:   keyId,
		AuthorityKeyId: caCert.AuthorityKeyId,
		NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:       time.Now().AddDate(2, 0, 0).UTC(),
	}

	// set IP-addesses and Server Alternate Names
        for _, name := range altnames {
                if ip := net.ParseIP(name); ip != nil {
                        template.IPAddresses = append(template.IPAddresses, ip)
                } else {
                        template.DNSNames = append(template.DNSNames, name)
                }
        }


	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, errors.New("Failed to generate a parsable certificate")
	}

	return certs[0], priv, nil
}


var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64       = big.NewInt(maxInt64)
)


func randBigInt() (value *big.Int) {
	value, _ = rand.Int(rand.Reader, maxBig64)
	return
}

func randBytes() (bytes []byte) {
	bytes = make([]byte, 20)
	rand.Read(bytes)
	return
}
