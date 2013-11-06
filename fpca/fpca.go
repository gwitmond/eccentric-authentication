// Eccentric Authentication Suite
//
// Tools and utilities to create an Eccentric Authentication application.
// Makes it easy to do correctly.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

// Code that implements the First Party Certificate Authority

package fpca

import (
	//"io/ioutil"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	CryptoRand "crypto/rand"
	//MathRand "math/rand"
	"math/big"
	"time"
	//"encoding/pem"
	//"errors"
	//"fmt"
	//"log"
)

// The First Party Certificate Authority signs 
type FPCA struct {
	Namespace string // the name space that we are signing. I.E. <cn>@@example.com. Specifiy the part after the @@."
	CaCert        *x509.Certificate         // The SubCa that signs the client certificates.
	CaPrivKey   *rsa.PrivateKey // The private key of the SubCA that does the (actual) signing.
}

// SignUpPubkey signs a public key, cn combo with our CAPrivKey and returns the raw DER-encoded bytes.
// We sign anything. Caller is responsible for <cn>@@<namespace> validation.
func (fpca *FPCA) SignClientCert(CN string, pubkey *rsa.PublicKey) ([]byte, error) {
	serial := randBigInt()
	keyId := randBytes(20)
	template := x509.Certificate{
                Subject: pkix.Name{
                        CommonName: CN,
		},
		// add restrictions: CA-false, authenticate, sign, encode, decode, no server!
                SerialNumber:   serial,
                SubjectKeyId:   keyId,
                AuthorityKeyId: fpca.CaCert.AuthorityKeyId,
                NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),  // this leaks time of signing.
                NotAfter:       time.Now().AddDate(10, 0, 0).UTC(),   // ten years.
		IsCA:           false,
		KeyUsage:       x509.KeyUsageDigitalSignature + x509.KeyUsageContentCommitment + x509.KeyUsageDataEncipherment + x509.KeyUsageKeyAgreement,
		// set ExtKeyUsageAny to allow both login as well as message signing.
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
        }

	// Create CLIENT certificate 
	derBytes, err := x509.CreateCertificate(CryptoRand.Reader, &template, fpca.CaCert, pubkey, fpca.CaPrivKey)
	if err != nil {
		return nil, err
	}
	return derBytes, nil
}


//// Utils

var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64       = big.NewInt(maxInt64)
)

func randBigInt() (value *big.Int) {
        value, _ = CryptoRand.Int(CryptoRand.Reader, maxBig64)
        return
}

func randBytes(count int) (bytes []byte) {
        bytes = make([]byte, count)
        CryptoRand.Read(bytes)
        return
}