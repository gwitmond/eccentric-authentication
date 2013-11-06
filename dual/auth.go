// Eccentric Authentication Suite
//
// Tools and utilities to create an Eccentric Authentication application.
// Makes it easy to do correctly.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package dual

import (
	"net/http"
	"log"
	"github.com/bpowers/seshcookie"
	"github.com/gwitmond/eccentric-authentication"
)

// dual.AuthHandler accepts both Eccentric Authenticated Client certificates 
// as well as email address and password accounts.
// It uses session cookies to tell the accountName to the downstream Handelrs.
type AuthHandler struct {
        Handler http.Handler
        Ecca *eccentric.Authentication  // details where the register-service is located.
        Template string   // template to be shown when user is not logged in.
}

func (ah *AuthHandler) debug(format string, params... interface{}) {
        if ah.Ecca.Debug == true {
                log.Printf(format, params...)
        }
}

func (ah *AuthHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
        session := seshcookie.Session.Get(req)
        ah.debug("DualAuthHandler using session: %#v\n", session)

        // the http.Server has already verified any client certificate (as we've specified at start-up)
        if len(req.TLS.PeerCertificates) == 1 {
                // Always set the account to the certificate's commonname if we have one.
                // The user may have changed accounts in their ecca-proxy.
                cn := req.TLS.PeerCertificates[0].Subject.CommonName
                session["accountName"] = cn 
                ah.debug("DualAuthHandler has found an ECCA user; setting session['accountName'] to cn: %#v\n", cn)
        } else {
                // Check if we have a session set by /login and /setup
                acctName, loggedIn := session["accountName"]
                if loggedIn == false {
                        // redirect to ecca login page (with links to /login and /signup)
                        ah.debug("DualAuthHandler: No cert and no pw-account. Redirecting to %#v\n", ah.Template)
                        ah.debug("Ecca params are: %#v\n", ah.Ecca)
                        ah.Ecca.SendToLoginPage(rw, ah.Template, nil)
                        return
                }
                ah.debug("DualAuthHandler has found a logged in user: %#v\n", acctName)
        }
        // Run the application request.
        ah.debug("DualAuthHandler finished; run the next hander: %#v\n", ah.Handler)
        ah.Handler.ServeHTTP(rw, req)
}
