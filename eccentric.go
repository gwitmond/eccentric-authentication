// Eccentric Authentication Suite
//
// Tools and utilities to create an Eccentric Authentication application.
// Makes it easy to do correctly.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package eccentric

import (
	"net/http"
	"html/template"
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"regexp"

	"github.com/gwitmond/unbound" // also does DANE parsing
)

// Authentication contains the configuration parameters for the application.
// RegisterURL:  URL of the page at the FPCA  where the user agent signs up for a certificate
//                         example:  "https://register-dating.wtmnd.nl:10444/register-pubkey"
// Debug: Boolean to determine debugging
type Authentication struct {
	RegisterURL   string
	Templates *template.Template
	Debug bool
}

func (ecca *Authentication) debug (format string, params... interface{}) {
	if ecca.Debug == true {
		log.Printf(format, params...)
	}
}

// HTTP handlers

// templateHandler returns a handler that serves HTTP requests by
// applying the named template without parameters to the template
func (ecca *Authentication) TemplateHandler (templateName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ecca.debug("Ecca: rendering template: %q\n", templateName)
		check(ecca.Templates.ExecuteTemplate(w, templateName,  nil))
	})
}

// loggedInHandler returns a handler that calls the given handler when the client uses a certificate to authenticate.
// Otherwise it sends a Ecca-login page
func (ecca *Authentication) LoggedInHandler (handler http.HandlerFunc, templateParams ...interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Require to be logged in.
		ecca.debug("Ecca: Checking if user is logged in")
		if len(req.TLS.PeerCertificates) == 0 {
			ecca.debug("Ecca: User does not have a (correct) certificate, sending login page\n")
			ecca.SendToLoginPage(w, templateParams...)
                return
		}
		// User is logged in. Run the application handler.
		ecca.debug("Ecca: User has certificate. CN is: %v\n", req.TLS.PeerCertificates[0].Subject.CommonName)
		handler.ServeHTTP(w, req)
	})
}


// SendToLoginPage redirects the browser to the sites' FPCA. 
// It sets the WWW-Authenticate header so the user agent knows where to sign up.
// It sets response headers so no output may have been written so far.
func (ecca *Authentication) SendToLoginPage (w http.ResponseWriter, template_params ...interface{}) {
        w.Header().Set("Content-Type", "text/html")
	// Tell the user-agent where to obtain a certificate.
        w.Header().Set("WWW-Authenticate", "Ecca type=\"public-key\" register=\"" + ecca.RegisterURL + "\"")
        w.WriteHeader(401)
	// Render a template if we have one
	if (len(template_params) >= 1) {
		template := (template_params[0]).(string)
		
		check (ecca.Templates.ExecuteTemplate(w, template, template_params[1:]))
	} else {
		w.Write([]byte("You need to register.\n"))
	}
}



// ReadCert, read (server) certificate file or panic
func ReadCert(certFile string) (*x509.CertPool) {
        pool := x509.NewCertPool()

        certPEMBlock, err := ioutil.ReadFile(certFile)
        if err != nil {
                panic("Cannot read certificate file " + certFile)
        }
        ok := pool.AppendCertsFromPEM(certPEMBlock)
        if !ok  {
                panic("Cannot parse certificate file " + certFile)
        }
        return pool
}

type AppHandler func(http.ResponseWriter, *http.Request) error

// Catch panics and show them.
func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		rec := recover()
		if rec != nil {
			fmt.Printf("Panic detected: %#v\n", rec)
 			http.Error(w, fmt.Sprintf("Panic: %#v", rec), 500)
		}
	}()
	err := fn(w, r)
	if err != nil {
		fmt.Printf("Error detected: %v:\n", err.Error())
		http.Error(w, err.Error(), 500)
	}
}



// ValidateEccentricCertificate verifies that the given certificate parses to a real x509 certificate 
// and that it is signed by the FPCA
// DANE/TLSA record it specifies in the CN.
// TODO: Deprecate this function as it handles only direct signing by the FPCA, no SubCAs
// Use ValidateEccentricCertificateChain instead
func ValidateEccentricCertificate(cl_cert  *x509.Certificate) (caCert *x509.Certificate, err error) {
	log.Printf("Validate Eccentric Certificate got client certificate: Issuer: %#v\nand Subject: %#v", cl_cert.Issuer, cl_cert.Subject)

	// Check the cn if it has the @@ in it.
	cn := cl_cert.Subject.CommonName  // the chosen userid@@realm
	log.Printf("Subject CommonName is %v\n", cn)
	_, _, err = ParseCN(cn)
	if err != nil { return nil, err }

	// Now fetch the issuer. That must be the FPCA.
	issuer := cl_cert.Issuer.CommonName
	if issuer == "" { 
		return nil, errors.New("Certificate does not look like an Eccentric Authenticated client certificate. It has an empty Issuer.CommonName. We expect the fqdn of its FPCA.")
	}
	unb := unbound.New()
	caCert, err = unb.GetCACert(issuer)
	check(err)
	log.Printf("Got certificate: Issuer: %#v\nand Subject: %#v", caCert.Issuer, caCert.Subject)
	
	err = cl_cert.CheckSignatureFrom(caCert)
	check (err) // TODO: give out neat error at validation failure, not a panic.

	return caCert, nil
}

// ValidateEccentricCertificate verifies that the given certificate parses to a real x509 certificate 
// It is signed by the FPCA
// DANE/TLSA record it specifies in the CN.
func ValidateEccentricCertificateChain(cl_cert  *x509.Certificate, root *x509.Certificate) (chain []x509.Certificate, err error) {
	log.Printf("Validate Eccentric Certificate Chain got client certificate: Issuer: %#v\nand Subject: %#v", cl_cert.Issuer, cl_cert.Subject)

	// Check the cn if it has the @@ in it.
	cn := cl_cert.Subject.CommonName  // the chosen userid@@realm
	log.Printf("Subject CommonName is %v\n", cn)
	_, _, err = ParseCN(cn)
	if err != nil { return nil, err }

	// Now fetch the chain
	chain, err = FetchCertificateChain(cl_cert, root)
	return 
}

// Fetch the certificate chain from the given certifcate upto the root.
// Return the chain that validates the cl_cert.
// This version looks up certificate in DNS based upon their CommonName.
// ie. FPCA.domain.tld, ROOTCA.domain.tld.
// We stop searching when certX.Issuer.CN == Root.Subject.CN
// We return at least 1 certificate, the Root.
// TODO: Get certificates based upon Serials
func FetchCertificateChain(cl_cert *x509.Certificate, root *x509.Certificate) ([]x509.Certificate, error) {
	chain, err := fetchCertificateChain(cl_cert, root)
	// reverse to make the Root certificate last, as OpenSSL likes it.
	for i, j := 0, len(chain)-1; i<j; i,j = i+1, i-i {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, err
}

func fetchCertificateChain(cl_cert *x509.Certificate, root *x509.Certificate) (chain []x509.Certificate, err error) {
	// check if cl_cert is signed by Root
	if (cl_cert.Issuer.CommonName == root.Subject.CommonName) {
		// client cert is signed by Root, there are no (more) intermediaries. We're done.
		chain = append(chain, *root)
		return chain, nil
	}

	issuer := cl_cert.Issuer.CommonName
	if issuer == "" { 
		// chain is empty at this point.
		return chain, errors.New("Certificate does not look like an Eccentric Authenticated Intermediate certificate. It has an empty Issuer.CommonName. We expect the fqdn of its FPCA.")
	}
	unb := unbound.New()
	caCert, err := unb.GetCACert(issuer)
	check(err)
	log.Printf("Got certificate: Issuer: %#v\nand Subject: %#v", caCert.Issuer, caCert.Subject)
	
	// check if the signature matches
	err = cl_cert.CheckSignatureFrom(caCert)
	check (err) // TODO: give out neat error at validation failure, not a panic.
	
	// recurse to get higher up the tree.
	chain, err = FetchCertificateChain(caCert, root)
	if (err != nil) { return } // empty, err
	chain = append(chain, *caCert)
	return // chain, nil
}


// FetchRootCA fetches the RootCA certificate for the given hostname.
func FetchRootCA(hostname string) (*x509.Certificate, error) {
	rootname := "RootCA." + hostname // per definition
	unb := unbound.New()
	rootCaCert, err := unb.GetCACert(rootname)
	check(err)
	log.Printf("Got certificate: Issuer: %#v\nand Subject: %#v", rootCaCert.Issuer, rootCaCert.Subject)
	return rootCaCert, err
}


// Parse a single (client) certificate,
// Return a x509.Certificate structure
// To Be Deprecated. Use ParseCertString or ParseCertByteA instead
func ParseCert(cert string) (*x509.Certificate, error) {
	return ParseCertString(cert)
}

// Parse a single (client) certificate,
// Return a x509.Certificate structure
func ParseCertString(cert string) (*x509.Certificate, error) {
	return ParseCertByteA([]byte(cert))
}

// Parse a single (client) certificate,
// Return a x509.Certificate structure
func ParseCertByteA(cert []byte) (*x509.Certificate, error) {
	// decode pem..., 
        pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		return nil, errors.New("Did not receive a PEM encoded block of data")
	}
	// check PEM
	if pemBlock == nil {
		return nil, errors.New("Did not receive a PEM encoded certificate")
	}

        // check type..., 
        if pemBlock.Type != "CERTIFICATE" {
                return nil, errors.New("Did not receive a PEM encoded certificate")
        }

        // parse der to validate the data...,
       return x509.ParseCertificate(pemBlock.Bytes)
}



// match <cn>@@<fqdn> with ascii domain names
var cnRE = regexp.MustCompile(`^([^@]+)@@([a-zA-Z0-9._]+)$`)

// parseCN parses the string and returns the username and realm parts if it mathes the
// cnRE - regular expression. Otherwise, it returns two empty strings.
func ParseCN(cn string) (username, realm string, err error) {
	match := cnRE.FindStringSubmatch(cn)
	// fmt.Printf("match %v gives: %#v\n", cn, match)
	if len(match) == 3 {
		return match[1], match[2], nil
	}
	return "", "", errors.New("Certificate does not look like an Eccentric Authenticated client certificate. It has no <cn>@@sitename in the Subject.CommonName.")
} 

func PEMEncode(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func PEMDecode(pemBytes []byte) x509.Certificate {
	block, _ := pem.Decode(pemBytes)
        certs, err := x509.ParseCertificates(block.Bytes)
        check(err)
        if len(certs) != 1 {
                check(errors.New(fmt.Sprintf("Cannot parse CA certificate from database. Received: %#v which parsed to %#v\n", pemBytes, certs)))
        }
        return *certs[0]
}

func check(err error) {
        if err != nil {
                panic(err)
        }
}
