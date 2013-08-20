package main

import (
        //"crypto/rand"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        //"crypto/x509/pkix"
        "encoding/pem"
        //"errors"
        "io"
	"os"
        //"math/big"
        //"time"
	"text/template"
	"fmt"
	"github.com/gwitmond/eccentric-authentication/utils/camaker"
)

// Change the name of your application site. All other names are based upon that.
var sitename = "www.RentaNode.nl"
var registersitename = "Register.RentaNode.nl"

var fileprefix = "rentanode" // the prefix for the RootCA and FPCA keys and certificates.
var RootCAorg = "The Root CA that identifies all that belongs to " + sitename 
var RootCAcn = "RootCA." + sitename
var FPCAorg = "The FPCA for " + sitename
var FPCAcn = "FPCA." + sitename

func main() {
	// Generate a self signed CA cert & key. 
	// This is the Root CA key/cert.
	caCert, caKey, err := camaker.GenerateCA(RootCAorg, RootCAcn, 4096)
	handle(err)
	writePair(fileprefix + "RootCA", caCert, caKey)

	// Generate the FPCA Key and certificate that sign the client certificates
	fpcaCert, fpcaKey, err := camaker.GenerateFPCA(FPCAorg, FPCAcn, caCert, caKey, 3072)
	handle(err)
	writePair(fileprefix + "FPCA", fpcaCert, fpcaKey)

        // Generate a site key and cert  signed by our RootCA
        siteCert, siteKey, err := camaker.GenerateCert(sitename, caCert, caKey, 1024)
        handle(err)
	writePair(sitename, siteCert, siteKey)

        // Generate a FPCA TLS key sign its certificate with our Root CA.
	// So customers can use https to sign up.
        regCert, regKey, err := camaker.GenerateCert(registersitename, caCert, caKey, 4096)
        handle(err)
	writePair(registersitename, regCert, regKey)

	// Generate TLSA records with RootCaCert
	genTLSA("_443._tcp." + sitename, caCert)               // sites are signed by the RootCA. 
	genTLSA("_443._tcp." + registersitename, caCert)

	// These form a certificate chain. Not endpoints of tls-connections. Therefore no "_443.tcp" specifiers.
	// eg: fcpa.sitename.example.org TLSA 2 0 0 <key material>
	genTLSA(FPCAcn, fpcaCert)           // The users can fetch the FPCA-certificate here for validations.
	genTLSA(RootCAcn, caCert)           // And the root ca based upon the FPCA-Issuer-CN.
}

// genTLSA generate a TLSA 2 0 0 record for the given name and certificate
// Make sure to add _443._tcp for certificates uses in TLS-connections. That's what DANE requires.
// But leave them out for Eccentric certificate chains. That allows cn -> DNSSEC chaining.
func genTLSA(name string, cert *x509.Certificate) {
	// choose one of these two methods. The first is the best.
	// t, err := template.New("tlsa").Parse(`{{ define "tlsa" }}{{ .name }}.    IN   TLSA ( 2 0 0 {{ .hex }} ){{ end }}`)
	t, err := template.New("tlsa").Parse(`{{ define "tlsa" }}{{ .name }}.    IN   TYPE52 \# {{ .len }}  ( 020000 {{ .hex }} ){{ end }}`)
	handle(err)
	f, err := os.OpenFile(name + ".bind", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
        handle(err)
	defer f.Close()
	err = t.ExecuteTemplate(f, "tlsa", map[string]interface{}{
		"name": name,
		"hex": fmt.Sprintf("%x", cert.Raw),
		"len": len(cert.Raw) + 3, // +3 for the 2 0 0 characters.
	})
	handle(err)
}

func writePair(serverName string, cert *x509.Certificate, key *rsa.PrivateKey) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})	
	err := writeFile(serverName + ".cert.pem", cBytes, 0444)
	handle(err)
	err = writeFile(serverName + ".key.pem", kBytes, 0400)
	handle(err)
}

// writeFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm;
// It does not overwrite files.
func writeFile(filename string, data []byte, perm os.FileMode) error {
        f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
        if err != nil {
                return err
        }
        n, err := f.Write(data)
        f.Close()
        if err == nil && n < len(data) {
                err = io.ErrShortWrite
        }
        return err
}



// Generate a key
func generatePair(serverName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	cert, key, err := camaker.GenerateCert(serverName, caCert, caKey, 1024)
		
	if err != nil {
		return tls.Certificate{}, err
			
		}
	return x509Pair(cert, key)
}

func x509Pair(cert *x509.Certificate, key *rsa.PrivateKey) (tls.Certificate, error) {
	cBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	kBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	
	return tls.X509KeyPair(cBytes, kBytes)
}


func handle(err error) {
	if err != nil {
		panic(err.Error())
	}
}
