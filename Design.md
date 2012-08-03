Eccentric Authentication
================


Protocol Design
-------------

### Definitions

hoster: person running a server with some services and a local CA to sign up users;

service: a web site that is configured to accept certificates from the local CA;

local CA: A Certificate Authority used to bind the users' public key and username together into an identity;
This CA is not globally trusted. It's only trusted by the hoster (axiomatic) and the clients that sign up.

client: Person that signs up for the service provided by hoster;

identity: a combination of username and the name of the local CA, as signed into the certificate; Clients can create as many identities at as many local CA's as they wish; 

username: the name the user chooses for his identity at the CA; 

common name: the SSL-name for the field that carries the username of the user of the certificate;

Not part of Eccentic Authentication (but used in the description):

Global CA: a well known CA, trusted by most common web browsers and operating systems, whether the user agrees or even knows about it; Identities signed by global CA have no privacy at all;

In-house CA: a CA operated and trusten in a small community, say a company. Usually, system operators take care of key management. Identities are well known and offer no privacy within the group.


### Identities

The difference with global or in-house CA's is the signing policy. Where global CA's need to validate the users' real identity before signing a certificate that proofs it's him, the local CA has the most simple requirement: 

	The common name must be unique within the CA.

When that requirement is met the CA can sign certificate requests. 

The certificate binds the common name and the public key into the certificate.

	The certificate binds a username to a public/private keypair into a digital idenitity or pseudonym.

It allows the owner of the key to control the use of his chosen username on the site. Only he can log in with this username at the site.

It also allows the site owner to recognise the user when he returns to the site. It works even better than Cookies as cookies can be copied, requiring a password to validate the user. Although it sounds scary that the site can recognise recurring visits even better than before, the user agent (web browser) is very capable of taking care of that privacy aspect. See the section on Clients/User Agent.

The certificate really represents an electronic pseudonym. The user can use it to write a blog and create a following based upon this username and writings. 

But nowhere had our user specify any identifying infomation, such as a passport or even an email address.

As identities are so easy to obtain for a user, he creates many identities at as many sites. Maybe he has faked all the replies on his blog himself controlling many identities at the blog site, who knows.

### Local CA

The local CA operates a Certificate Authority system. 

It's a CA like any other out there, it has a private CA-key for signing must be kept secret. A leak of the CA-key compromises all certificates signed with it. A CA has no need to run on the same hardware as the services the hoster provides. It's best to run it on separate systems. Given the very easy validation requirements, it could even be outsourced easily and cheaply. See later for Nested CA structure how to reduce the risks.

#### Implementation

The local CA operates a web site with a few pages. It offers the user to create a username. The site might assist the user in selecting a unique name. 

	When satisfied with the username, the user creates and submits his Certificate Signing Request to the CA. 

The user creates a new public/private keypair and signs the Request with that pair. The user keeps the private key secret.

	The CA performs the uniqueness validation on the username and signs the request. 

The uniqueness validation makes sure that any identity is used only once. Otherwise, anyone could create multiple certificates for any name, defeating the identity. (It would lead to the combination of username and serial number to be unique, but that is not so userfriendly.)

	The CA returns the freshly signed certificate in the same HTTP-connection that the user used to submit.

It's required that the whole CSR -> Validate -> Sign -> Certificate chain happens in a single HTTPS request. This is imperative as we don't know anyway to contact the user after the connection has broken. If we were to request an email address that would be a big burden on the user to either get a temporary anonymous email address or lose his privacy.

	The CA returns an error when the username is not unique for the CA.

When the username has already been used for a certificate, the CA rejects the signature. The user can try again with a newly chosen username.

### Hoster

The hoster is the person running a site that uses Eccentric Authentication to authenticate its users.

#### Free accounts

The hoster doesn't care about the real identities of his users. He uses EccA to let users create an identity/pseudonym for themselves. 

All he needs to do is:

	Configure the service to accept client authentication from his local CA.

He knows that all users that signed up via his CA have a unique username, that it's task.

The server can keep state on users based solely on the username. It means you can ditch long term cookies too. People keep deleting those anyway and as they are easily copied, you cannot trust these for authentication. 

#### Paid accounts

As the hoster can uniquely identify his users by their username, he can ask them to pay for certain features on the site and link the payment to the account name. 

The user can decide wheter to link his Eccentric identity to his bank account number. Even when the user uses a payment system that's tied to his identity, he still benefits from the protocol as it provides a better user experience than username and password.

Would the user pay via a privacy preserving payment method he can aquire services without losing his privacy. 


#### Outsourced CA

A hoster could run his own CA or outsource it to a third party he trusts. All he needs to do is a random check to see that the outsourced CA really creates unique usernames/common names. The outsourced CA should be used only to create certificates for that site. 

A person running outsourced CA's should set up a separate CA for each of his customers, with a separate private key and separate name space. He could run it all on one single host. 


#### Easier and cheaper

Note, there is no need to store any data on users except their username. Without personally identifiable data, you have no need to spend money on securing it.

Furtermore, your site is most likely cheaper to run than one based on passwords because you can ditch the infrastructure for resetting passwords, validate and change email addressess.

### Clients
	
Clients are the people like you and me using web sites every day. We would like to sign up to some sites to ventilate our opinion on the discusion boards without giving away our real identity. It's just like a conversation at my local cafe. The people there might remember my face and my opinions on the topic at hand. Whether they agree or not is a diffent subject. Each patron is free to ventilate his opinions to anyone who listens. They may have their opinion of me but they won't know more than how I look like and what I blabbered about. That's the amount of privacy I expect at the local bar.

People may recogise my identity (a self chosen name) and the things I was blogging about but don't know more about me than I was willing to divulge. Whether they agree or not is a different subject. Each participant is free to add their view to the discussion. They won't know more than my username/identity and what I blabbered about. That's the amount of privacy I envision on the net.

#### User Agent

The user agent must make it easy to create identities and use the correct ones for the sites. The requirements are:

	Perform all key and certificate handling.

The users creates the username, the browser takes care of all keys and certificates. The agent offers a login-button on the window frame. With a click the user can log in with one of his identities at the site.

There must be a log out button. Right now, the only way to log out is to close the browser application. The agent should have a log out button that stops using the authenticated session. The user can log in with any other identities he has for the site. It should be careful not to leak the fact that one user has multiple identities. (Users concerned should take additional measures against monitoring if this is an important concern). 

	Pin the certificate to the website it was requested for.

When the user signs up, the agent remembers the site for which the identity was created. When the user later browses to the site again the agent offers only that identity to log in. It must not offer other identities as the user 

The agent must make it easy to select the correct identity. And it should be difficult to select the wrong id. When a wrong identity is chosen, the site learns about that identity. It might be embarrassing. 

	Allow the user to assign security policies to identies.

Not all identities the user has created should be treated equal. A user might want to log in automatically to some sites whenever he browses to the site. Yet for other sites he wants to specify a password before he can log in. For example, at his bank-site. 

The browser should make it easy to recognise the identities and sites they belong to and to assign security policies to them. There should be a way to transfer some private keys to a smart card to create a physical barrier before the key can be used.
