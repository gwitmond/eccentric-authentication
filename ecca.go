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
//
type Authentication struct {
	RegisterURL   string
	Templates *template.Template
	
}

// HTTP handlers

// templateHandler returns a handler that serves HTTP requests by
// applying the named template without parameters to the template
func (ecca *Authentication) TemplateHandler (templateName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		check(ecca.Templates.ExecuteTemplate(w, templateName,  nil))
	})
}

// loggedInHandler returns a handler that calls the given handler when the client uses a certificate to authenticate.
// Otherwise it sends a Ecca-login page
func (ecca *Authentication) LoggedInHandler (hander http.HandlerFunc, templateParams ...interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Require to be logged in.
		if len(req.TLS.PeerCertificates) == 0 {
			ecca.SendToLogin(w, templateParams...)
                return
		}
		// Just run the application login
		hander.ServeHTTP(w, req)
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

// type appHandler func(http.ResponseWriter, *http.Request) error

// // Catch panics and show them.
// func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	defer func() {
// 		rec := recover()
// 		if rec != nil {
// 			fmt.Printf("Panic detected: %#v\n", rec)
// 			http.Error(w, fmt.Sprintf("Panic: %#v", rec), 500)
// 		}
// 	}()
// 	err := fn(w, r)
// 	if err != nil {
// 		fmt.Printf("Error detected: %v:\n", err.Error())
// 		http.Error(w, err.Error(), 500)
// 	}
// }


// ValidateEccentricCertificate verifies that the given certificate (string) parses to 
func ValidateEccentricCertificate(cert string) (username, site string, err error) {
	cl_cert, err := ParseCert(cert)
	if err != nil { return "", "", err }
	cn := cl_cert.Subject.CommonName  // the chosen userid@@realm
	
	username, site = ParseCN(cn)
	if username == "" || site == "" {
		return "", "", errors.New("Certificate does not look like an Eccentric Authenticated client certificate")
	}

	unb := unbound.New()
	caCert, err := unb.GetCACert(site)
	check(err)
	log.Printf("Got certificate: %#v\n", caCert)
	
	err = cl_cert.CheckSignatureFrom(caCert)
	check (err) // TODO: give out neat error at validation failure, not a panic.

	return site, username, nil
}

// Parse a single (client) certificate 
func ParseCert(cert string) (*x509.Certificate, error) {
	// decode pem..., 
        pemBlock, _ := pem.Decode([]byte(cert))
	fmt.Printf("pemBlock is: %#v\n", pemBlock)
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

func check(err error) {
        if err != nil {
                panic(err)
        }
}