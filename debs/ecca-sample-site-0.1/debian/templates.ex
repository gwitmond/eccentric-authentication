Template: ecca-sample-site/servername
Type: string
Default: www.yourdomain.org
Description: The servername of your web server
 This is the server name of your web server, the server that will serve what your 
 customers come for.
 .
 The servername you specify here will be used to configure the server certificate. 
 It allows your clients to connect to your site securely.
 .
 When in doubt choose: www.yourdomain.org.
 .
 This will be used in the server configuration and the server certificate.

Template: ecca-ca/countrycode
Type: string
Default: NL
Description: The countrycode of your country:
 The countrycode is the two-letter code of your country.
 .
 This is used to configure your RootCA and SubCA. It will be 
 used on every client certifcate you will create.

Template: ecca-ca/state-or-province
Type: string
Default: Zuid-Holland
Description: The State or Province where you are located:
 The State or Province is used to configure your RootCA and SubCA.
 It will be used on every client certifcate you will create.

Template: ecca-ca/locality
Type: string
Default: Rotterdam
Description: The city where you are located:
 The City is used to configure the your RootCA and SubCA.
 It will be used on every client certifcate you will create.

Template: ecca-ca/organization
Type: string
Default: Your Company
Description: The name of your company:
 The company name is used to configure your RootCA and SubCA.
 It will be used on every client certifcate you will create.

Template: ecca-ca/organizational-unit
Type: string
Default: Your Organisation CA
Description: The department of your company:
 The organizational unit name is used to configure your RootCA and SubCA.
 It will be used on every client certifcate you will create.

Template: ecca-ca/email-address
Type: string
Default: my@my-organisation.tld
Description: Your email address:
 The email address is used to configure your RootCA and SubCA.
 It will be used on the RootCA certficate and server certificates.
 It should point to an address that handles customer queries on EcCA certificates.

Template: ecca-signer/servername
Type: string
Default: ecca.yourdomain.org
Description: The servername of your EcCA server
 This is the server name of your Eccentric Authentication server, the server that will 
 perform the user registration, the certficate signing.
 .
 The servername you specify here will be used to configure the server certificate. 
 It allows your clients to connect to your site securely.
 .
 When in doubt choose: ecca.yourdomain.org.
 .
 This will be used in the server configuration and the server certificate.
