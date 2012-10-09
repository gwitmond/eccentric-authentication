The same ideas as in README.md but in different word. Perhaps this
clears up some confusion from the README.


I've come up with a system to replace password authentication over the
internet with public key client certificates.

The problems with passwords are well known: They are either to weak to
provide security or too complex to remember them. And with the current
break-ins it has became apparent that many systems are too lax with
security to keep them safe.

While the use of password managers certainly helps to overcome the
remembering-part, the server side security is still unaddressed. (I.E.,
sites are still leaking passwords).

While client certificates are already in use, the current modus
operandus has a big problem too: The client certificates from the
global trusted CA's act as a digital passport. These identify the user
at every web visit and with every email.

So the price of the security they provide is total obliteration of
privacy. Although these global CA certificate have their use, it's too
high a price for most applications. That's why the world still uses
passwords. It provides users with the means to protect their identity
at an acceptable risk of disclosure.

The power of certificates is too good to be left unused. My proposal
tries to put the certficates to good use: provide better security at
authentication while protecting the privacy of the users.

Many, many CA's

The thing I do differently is that instead of having a few (hundred)
globally trusted CA's issuing certificates, I urge every web site to
run their own little CA that signs only their own users.

The users register at the site with no more than a self-chosen user
name and a public key. The CA of the site checks if the user is unique
and if so, signs a certificate binding the username with the users's
public key. This establishes a secure, unforgable, identity at the
site. Only the owner of the private key can successfully log in with
the certificate. As the certificate contains the username. The site
can recognize the user at later log in.

This solves a lot of problems we had with passwords:
- no more lost passwords, the browser does a better job at remembering
  long random blobs of data;
- no more phishing, the browser can't be fooled into signing in to a
  phishing site as they cannot impersonate the server certificate.
  (this also needs server certificate with pinning and DNSSEC/DANE);
- When the website gets hacked, there are no passwords to steal and use
  at another site. Remember, every site has its own CA.

These certificates have value only to the site that created it. And to
the user that signed up for one. There is no need to create a global
list of trusted certificate authorities like the one we have in our
browsers.

Examples

Every website that needs to identify users but doesn't need the users
real identity can use the system.  For example, when a site offers
blogs, they publish the chosen username with the blog entries and
comments. Over time, users can recognize other users on their
usernames and build a reputation.

On Naming:

I call it Eccentric Authentication.

The dictionary say about Eccentric:
 1) Deviating or departing from the center, not having the same center;
 2) Odd, strange.


For more details, and some unfinished code, check out
    https://github.com/gwitmond/eccentric-authentication
