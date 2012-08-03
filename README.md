Eccentric Authentication
========================

Eccentric Authentication provides secure and anonymous client certificates. No more passwords.


**Eccentric Authentication ditches the passwords**

You never need to use passwords to log in to any site anymore. All the problems with passwords, such as forgetting them, changing them every now and then or the more and more arcane rules that make passwords difficult. All gone.

**Eccentric Authentication gives security and privacy**

The technology is already built into every web browser and web server. And it's good technology. It secures many websites and their users against eavesdropping and makes ecommerce possible. But it doesn't provide any privacy the way it is currently used.

We can use this technology to ditch passwords and increase privacy of users at the same time. 
How? We use it in a slightly different way than what is currently done.

Current practise is that for a global Certificate Authority to sign a certificate for a person, the client has to provide his real identity including name, location, payment details. And it can take a few days to a week to get all the paperwork done. When you use that identity to log in, it provides your real identity to any site you use it for. And when you sign an email with it, it shouts your identity of the rooftops. Undeniably that it was you who wrote it. For years to come. It's a big burden. 

That's why client certificates are not used much on the web. And that's why we still have passwords. Accounts with passwords allow users to choose the amount of private details they want to divulge to a random web site, instead of giving it all away.

**Many, many CAs**

Eccentric Authentication uses client certificates for user authentication but instead of a few global CA's that want to know your identity, we envision a CA for every web site. 

There are a few simple rules:

1. Each website operator runs his own Certificate Authority;
2. Each website only accepts client certificates from its own local CA;
3. Each local CA signs any certificate request from any user as long as the username is unique for the CA; for free;
4. The whole Request -> Validate -> Sign -> Reply transaction happens in a single HTTPS request.

When users want to sign up for an account at your website, they choose a username, create a public/private keypair and issue a certificate request at your local CA. 

Your local CA validates that the username is still available. If so, it signs the request and creates a certificate. It returns the certificate in the same HTTPS-connection.

The user can use the certificate to log in to the site immediately.

The users' browser takes care of all key and certificate handling, making it a much smoother login process than passwords and emails. And much more secure. With privacy if the user wants to.
