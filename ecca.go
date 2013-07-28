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
			ecca.SendToLogin(w, templateParams...)
                return
		}
		// User is logged in. Run the application handler.
		ecca.debug("Ecca: User has certificate. CN is: %v\n", req.TLS.PeerCertificates[0].Subject.CommonName)
		handler.ServeHTTP(w, req)
	})
}


// SendToLogin redirects the browser to the sites' FPCA. 
// It sets the WWW-Authenticate header so the user agent knows where to sign up.
// It sets response headers so no output may have been written so far.
func (ecca *Authentication) SendToLogin (w http.ResponseWriter, template_params ...interface{}) {
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



// ValidateEccentricCertificate verifies that the given certificate parses to a real x509 certificate and matches the
// DANE/TLSA record it specifies in the CN.
//func ValidateEccentricCertificate(certstr string) (username, site string, cert *x509.Certificate, err error) {
func ValidateEccentricCertificate(cl_cert  *x509.Certificate) (username, site string, caCert *x509.Certificate, err error) {	    //cl_cert, err := ParseCert(certstr)
	//if err != nil { return "", "", nil, err }
	log.Printf("Got client certificate: Issuer: %#v\nand Subject: %#v", cl_cert.Issuer, cl_cert.Subject)

	// Check the cn if it has the @@ in it.
	cn := cl_cert.Subject.CommonName  // the chosen userid@@realm
	username, site = ParseCN(cn)
	if username == "" || site == "" {
		return "", "", nil, errors.New("Certificate does not look like an Eccentric Authenticated client certificate. It has no <cn>@@sitename in the Subject.CommonName.")
	}

	// Now fetch the issuer. That must be the FPCA.
	issuer := cl_cert.Issuer.CommonName
	if issuer == "" { 
		return "", "", nil, errors.New("Certificate does not look like an Eccentric Authenticated client certificate. It has an empty Issuer.CommonName. We expect the fqdn of its FPCA.")
	}
	unb := unbound.New()
	caCert, err = unb.GetCACert(issuer)
	check(err)
	log.Printf("Got certificate: Issuer: %#v\nand Subject: %#v", caCert.Issuer, caCert.Subject)
	
	err = cl_cert.CheckSignatureFrom(caCert)
	check (err) // TODO: give out neat error at validation failure, not a panic.

	return site, username, caCert, nil
}

// Parse a single (client) certificate
func ParseCert(cert string) (*x509.Certificate, error) {
	// decode pem..., 
        pemBlock, _ := pem.Decode([]byte(cert))
	if pemBlock == nil {
		return nil, errors.New("Did not receive a PEM encoded block of data")
	}
	log.Printf("pemBlock is: %#v\n", pemBlock.Type)
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
func ParseCN(cn string) (username, realm string) {
	match := cnRE.FindStringSubmatch(cn)
	// fmt.Printf("match %v gives: %#v\n", cn, match)
	if len(match) == 3 {
		return match[1], match[2]
	}
	return "", ""
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