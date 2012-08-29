Eccentric Authentication
========================

Eccentric Authentication provides secure and anonymous client certificates. It provides better security with less hassles than password authentication.


**Eccentric Authentication ditches the passwords**

When a site accepts EccA, you log in with a certificate. You don't need a password anymore. Your browser handles the certificates and offers you a button to log in and log out of the site. 

The problem with passwords are well knows, they are either too weak to provide resilience against cracking, or they are too difficult to remember one for every web site you've subscribed to. 
When you would use the same password, or a similar password at different sites, a break in at one site could lead to the breach of you account at another site. 

Many people now use password managers to handle passwords for them. Although they are a big improvement to be relieve you of the burden to remember each and every password, it is still a bit of hit and miss with respect to security.  
First you are still dependent on site to allow for strong passwords, some sites are lousy in that. 
Secondly, as many people still don't use password managers and backups, site owners offer the infamous Questions and Answers to be able to reset your password. Now you have the password problem in a different form: What was your mothers' maiden name at site A and what was it at site B?

All these problems are gone, when the site uses Eccentric Authentication.

**Eccentric Authentication gives security and privacy**

The technology needed is already built into every web browser and web server. It secures many websites and their users against eavesdropping and makes ecommerce possible. It's called Cryptography, PKI, SSL, HTTPS and Certificate Authorities. 

Current practise is that for a global Certificate Authority to sign a certificate for a person, the person has to provide his real identity including name, location, payment details. And it can take a few days to a week to get all the paperwork done. When you use that identity to log in, it provides your real identity to any site you use it for. It's a big burden. That's why client certificates from global CA's are not used much on the web. And that's why we still have passwords on the net as passwords allow users to choose the amount of private details they want to divulge to a random web site. 

We can use this certificate technology to ditch passwords and increase privacy of users at the same time.

How? We use it in a slightly different way than what is currently done. Instead of having a few (hundred) global Certificate authorities we create a certificate authority for each site. We call it the localCA. 

With EccA you have an (possibly different) identity for each website you register at.

**Many, many CA's. Many, many identities**

There are a few simple rules in the EccA protocol:

1. Each website operator runs his own local Certificate Authority;
2. Each website only accepts client certificates from its own local CA;
3. Each user chooses the username they want to use at each site; the only requirement is that the username is unique for the site it's requested; 
4. Each local CA verifies the uniqueness of the username and signs the certificate for that site; for free;
5. The whole Request -> Validate -> Sign -> Reply transaction happens in a single HTTPS request.

When users want to sign up for an account at your website, they choose a username, create a public/private keypair and issue a certificate request at your local CA. All the key handling should be done by the browser.

The local CA validates that the username is still available. If so, it signs the request and creates a certificate. It returns the certificate in the same HTTPS-connection.

The user can use the certificate to log in to the site immediately. 

**The certificate is the identity**

The certificate binds three data items together: The chosen username, the user's public key and the localCA's key. It forms a digital identity. The only requirement is the unique username. It allows a user to register at a site and use that name to build a reputation. Other users at that site can -- over time -- recognize that username and know that it was the same person who wrote it.

The EccA protocol does not require users to add an email-address, the identities are really anonymous. And users can create as many as they want at any site. So one can blog about politics under one identity and parenting under another. The users' browser should make it easy to do so.

**Benefits for site owners**

The benefits for users are clear: no more hassles with passwords, strong security due too cryptography and better privacy for users than with password authentication. There are benefits for site owners too.

As the EccA-protocol is wholly anonymous, you don't have personal details around. You won't be targeted by criminals that go after account data and passwords as you don't store any. All you need to store is the list of usernames to prevent signing the same name twice to different people. If criminals would break into your site they leave empty handed. It is probably cheaper to use EccA than to use passwords.

Although the protocol is anonymous and it does not provide a users' real identity, it does provide you with a sure way to recognize recurring users. You can be sure that it's the same user when he logs in with the same certificate. It's how cryptography works. All you need is to provide an incentive for people to sign up and use that same identity later.

**When not to use**

The EccA protocol is suited for sites where the real identity is not needed for operation. I.e. it's good for most blogs, newspapers, webshops. Probably good for 80% of the websites out there.

If you run a bank, a hospital or a city hall, you should use other mechanism to authenticate your clients. Every user can say they are Rockefeller and request a withdrawal. The EccA protocol does not provide for real identities to rely upon. As the security of the private key and certificate is under control of the user, you must use a second authentication mechanism to authenticate transactions. For example, a token generator with a chipcard and pincode.

