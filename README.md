Eccentric Authentication
========================

Eccentric Authentication provides secure and anonymous client
certificates. It provides better security with less hassles than
password authentication. This document describes how it achieves this.

**Summary**

Eccentric Authentication replaces the password login with client
certificate logins.

Each web site runs it's own CA.

The certificates are created when the customer registers for an
account at a website.

The only requirement that needs to be met before signing a
certificate is that the username is unique.

As these certificates contain no other information than the users'
chosen username, the certificates are therefore only trusted by the
site that created it and user who requested it.

The customer creates a new certificate at each site.

The user's web browser should do all the difficulties of certificate
handling, providing an easy to understand user interface.


**Eccentric Authentication ditches the passwords**

When you navigate to a site that accepts EcCA, you don't need a
password anymore. EcCA replaces passwords with cryptographic
certificates.

The problem with passwords are well known: They are either too weak to
provide resilience against cracking or they are too difficult to
remember. Furthermore, many people reuse the same password at
different sites so a security breach at one site could lead to the
breach of your account at another site.

Password managers are a big improvement over manual password
handling as they relieve you of the burden to remember each and every
password - a task better left to the computer, anyway.

With password managers however, you still have the hassle of
generating a good strong password for each site. Some managers offer
to do that for you as well but there are sites out there that are
really restricted in what they can accept. It makes password
generation less than ideal.

Secondly, as many people still don't use password managers nor
backups, site owners offer the infamous *Questions and Answers* to
reset your password. Now you have a different problem: What was your
mothers' maiden name at site A and what was it at site B?

All these hassles are gone, when the site provides Eccentric Authentication.

**Eccentric Authentication uses cryptographic certificates**

Eccentric Authentication uses cryptographic certificates to replace
the passwords. The technology we use is already built into every web
browser and web server. It's called SSL/TLS, HTTPS and Certificate
Authorities.

Current practise is that for a global Certificate Authority to sign a
certificate for a person, the person has to provide his real identity
including name, location, payment details. It can take a few days
to a week to get all the paperwork done. When you use that identity to
log in, it provides your real identity to any site you use it
for. 

You pay a (high) price to get a certificate and lose all privacy on
the web when you use it.  That's why client certificates from global
CA's are not used much on the web.

And that's why we still have passwords on the net. Using passwords
allow users to choose the amount of private details they want to
divulge to a random web site.

Eccentric Authentication uses this certificate technology to get rid
of the problems we encouter with passwords while providing the same
level of privacy for the customers.


**Many, many CA's. Many, many identities**

We use a Certificate Authority for each web site. We call it the
LocalCA. 

These are the rules of the protocol.
1. Each website operator runs his own local Certificate Authority;
2. Each website only accepts client certificates from its own local CA;
3. Each user chooses the username they want to use at each site; the
   only requirement is that the username is unique for the site;
4. Each local CA verifies the uniqueness of the username and signs the
   certificate for that site; for free;
5. The whole Request -> Validate -> Sign -> Reply transaction happens
   in a single HTTPS request.

The user can use the certificate to log in to the site immediately.

**The certificate is the identity**

The certificate binds three data items together: The chosen username,
the user's public key and the localCA's key. It forms a digital
identity. The only requirement is the unique username. It allows a
user to register at a site and use that name to build a
reputation. Other users at that site can -- over time -- recognize
that username and know that it was the same person who wrote it.

The EcCA protocol does not require users to add an email-address, the
identities are really anonymous. And users can create as many as they
want at any site. So one can blog about politics under one identity
and parenting under another. The users' browser should make it easy to
do so.

**Benefits for site owners**

The benefits for users are clear: no more hassles with passwords,
strong security due too cryptography and better privacy for users than
with password authentication. There are benefits for site owners too.

As the EcCA-protocol is wholly anonymous, you don't have to store personal
details in your database. You won't be targeted by criminals that go after
account data and passwords as you don't have any. All you need to
store is the list of usernames to prevent signing the same name twice
to different people. If criminals would break into your site they
leave empty handed. It is probably cheaper to use EcCA than to use
passwords.

Although the protocol is anonymous and it does not provide a users'
real identity, it does provide you with a sure way to recognize
recurring users. You can be sure that it's the same user when he logs
in with the same certificate. That's how cryptography works. All you
need is to provide an incentive for people to sign up and use that
same identity later.

**When not to use**

The EccA protocol is suited for sites where the real identity is not
needed for operation, I.e. it's good for most blogs, newspapers and
webshops. Probably it's good for 80% of the websites out there.

If you run a bank, a hospital or a city hall, you should use other
mechanism to authenticate your clients. The EcCA protocol does not
identify users with their real identity.

**Requirements for user interfaces**

Current web browsers, such as Firefox can use this protocol, both to
create the keys needed for the certificate as well as logging in with
the certificate.

However, its user interface is a bit spartan.

A plug-in that provides an easy user interface is severely need.

**More information**

For more information, feel free to inquire at guido@witmond.nl

Cheers, 

Guido Witmond.
Rotterdam.
