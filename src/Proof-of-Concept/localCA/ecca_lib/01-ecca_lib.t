#!/usr/bin/env lua

-- package.path="/opt/local/share/lua/5.1/?.lua;;"
require 'Test.More'


local csr = [[
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: CN=username
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:d4:b5:b8:62:3d:79:2d:c5:9c:1d:1c:87:73:f8:
                    f9:11:40:78:f0:35:3c:4d:c4:bf:6c:4f:51:86:e3:
                    0d:e4:fe:a7:d1:8e:9a:b3:2a:7a:a7:60:e6:14:9c:
                    50:e1:30:78:1f:a2:c6:95:35:ae:18:20:41:0c:24:
                    88:8c:07:6e:1b:87:d8:89:87:c5:a9:c7:51:5b:14:
                    fb:85:fd:34:70:6f:39:a9:b0:21:14:3a:5d:2c:78:
                    26:35:9e:43:b3:a0:ec:a1:5f:5e:a6:bd:3f:36:6e:
                    6f:e0:3c:60:04:4e:ca:e9:9c:55:d4:e7:5d:2b:dd:
                    f8:cb:da:e0:ef:b2:e4:5f:bb
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha1WithRSAEncryption
         79:ee:8f:4b:09:d6:3a:80:7f:cf:9f:bf:25:de:aa:99:3a:d9:
         58:66:34:ce:da:fe:f0:79:ab:ff:a9:f6:c2:27:a6:67:d4:d5:
         33:64:56:43:41:d4:a5:15:6c:b4:7f:71:b9:4d:28:90:b0:e8:
         4f:a1:d5:59:80:a3:fe:7c:ff:3a:17:a2:35:6c:31:43:5f:a6:
         e9:2f:8a:d4:5e:2c:85:6d:e9:73:ef:84:d2:1e:34:b9:a3:ca:
         54:48:7c:16:6e:02:00:92:8e:1f:48:35:18:2b:09:fe:84:06:
         45:3f:94:fc:48:af:9f:bc:ce:25:5c:bc:81:ed:f6:4c:d7:41:
         8b:6c
-----BEGIN CERTIFICATE REQUEST-----
MIIBUjCBvAIBADATMREwDwYDVQQDDAh1c2VybmFtZTCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEA1LW4Yj15LcWcHRyHc/j5EUB48DU8TcS/bE9RhuMN5P6n0Y6a
syp6p2DmFJxQ4TB4H6LGlTWuGCBBDCSIjAduG4fYiYfFqcdRWxT7hf00cG85qbAh
FDpdLHgmNZ5Ds6DsoV9epr0/Nm5v4DxgBE7K6ZxV1OddK934y9rg77LkX7sCAwEA
AaAAMA0GCSqGSIb3DQEBBQUAA4GBAHnuj0sJ1jqAf8+fvyXeqpk62VhmNM7a/vB5
q/+p9sInpmfU1TNkVkNB1KUVbLR/cblNKJCw6E+h1VmAo/58/zoXojVsMUNfpukv
itReLIVt6XPvhNIeNLmjylRIfBZuAgCSjh9INRgrCf6EBkU/lPxIr5+8ziVcvIHt
9kzXQYts
-----END CERTIFICATE REQUEST-----
]]

-- values in above CSR
local cn="username"
local pubkey=[[
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUtbhiPXktxZwdHIdz+PkRQHjw
NTxNxL9sT1GG4w3k/qfRjpqzKnqnYOYUnFDhMHgfosaVNa4YIEEMJIiMB24bh9iJ
h8Wpx1FbFPuF/TRwbzmpsCEUOl0seCY1nkOzoOyhX16mvT82bm/gPGAETsrpnFXU
510r3fjL2uDvsuRfuwIDAQAB
-----END PUBLIC KEY-----
]]

local cacert = [[
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12132218053149742367 (0xa85e4c0a4392551f)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=NL, O=Witmond Secure Software, OU=Witmond Eccentric CA, CN=ecca.witmond.nl
        Validity
            Not Before: Aug  4 18:43:54 2012 GMT
            Not After : Sep  3 18:43:54 2012 GMT
        Subject: C=NL, O=Witmond Secure Software, OU=Witmond Eccentric CA, CN=sub1.ecca.witmond.nl
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:9e:95:66:41:c8:f4:07:6f:fa:55:5b:f1:69:d0:
                    f2:25:2f:03:82:95:b3:5a:a3:78:3a:3d:f7:62:17:
                    48:0c:7b:b7:77:71:72:f8:de:f8:c4:f9:0f:f5:5e:
                    9c:4d:b0:50:9d:ab:f0:fd:45:d4:e1:fb:8a:dc:10:
                    96:c1:4c:cc:37:b7:16:dc:8d:2d:4f:e4:e5:21:29:
                    fd:93:64:cb:1a:28:26:d4:d4:0f:ee:b4:ee:55:b1:
                    05:5e:8d:7a:15:c4:ec:5d:51:91:86:f8:91:0c:5d:
                    a7:6f:ce:81:dd:5e:95:5a:0f:1c:78:e2:b6:53:20:
                    74:d5:a8:72:01:d5:ee:d2:ef
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                12:B4:2C:BE:21:A4:A8:F4:FE:C9:CF:62:92:DA:6D:C7:9C:9A:65:85
            X509v3 Authority Key Identifier: 
                keyid:FA:01:54:84:86:27:E2:EE:5D:4E:B2:41:46:D0:E8:70:C2:A0:4E:A6

            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha1WithRSAEncryption
         0d:9f:24:d9:62:d0:8f:74:4c:4f:e3:fa:bd:6d:e8:33:a6:f6:
         97:e1:b4:18:5d:36:0c:73:e5:f7:c9:b6:69:76:fa:cc:8d:8f:
         8b:bb:f7:37:58:b8:eb:d6:e6:27:89:ec:a2:d8:43:b0:90:37:
         13:13:f5:86:86:c6:39:3e:75:35:68:68:35:bb:f0:96:0d:cf:
         1e:a2:16:0b:df:b7:eb:4d:22:00:5a:df:1d:f3:97:6b:de:80:
         3e:42:91:ae:2c:66:0a:3e:18:d2:b7:4f:6c:60:19:44:74:05:
         53:62:2e:0f:74:d1:d2:22:44:46:5c:3b:15:9d:07:c7:a1:b8:
         a2:f6
-----BEGIN CERTIFICATE-----
MIICozCCAgygAwIBAgIJAKheTApDklUfMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNV
BAYTAk5MMSAwHgYDVQQKDBdXaXRtb25kIFNlY3VyZSBTb2Z0d2FyZTEdMBsGA1UE
CwwUV2l0bW9uZCBFY2NlbnRyaWMgQ0ExGDAWBgNVBAMMD2VjY2Eud2l0bW9uZC5u
bDAeFw0xMjA4MDQxODQzNTRaFw0xMjA5MDMxODQzNTRaMG0xCzAJBgNVBAYTAk5M
MSAwHgYDVQQKDBdXaXRtb25kIFNlY3VyZSBTb2Z0d2FyZTEdMBsGA1UECwwUV2l0
bW9uZCBFY2NlbnRyaWMgQ0ExHTAbBgNVBAMMFHN1YjEuZWNjYS53aXRtb25kLm5s
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCelWZByPQHb/pVW/Fp0PIlLwOC
lbNao3g6PfdiF0gMe7d3cXL43vjE+Q/1XpxNsFCdq/D9RdTh+4rcEJbBTMw3txbc
jS1P5OUhKf2TZMsaKCbU1A/utO5VsQVejXoVxOxdUZGG+JEMXadvzoHdXpVaDxx4
4rZTIHTVqHIB1e7S7wIDAQABo1AwTjAdBgNVHQ4EFgQUErQsviGkqPT+yc9iktpt
x5yaZYUwHwYDVR0jBBgwFoAU+gFUhIYn4u5dTrJBRtDocMKgTqYwDAYDVR0TBAUw
AwEB/zANBgkqhkiG9w0BAQUFAAOBgQANnyTZYtCPdExP4/q9begzpvaX4bQYXTYM
c+X3ybZpdvrMjY+Lu/c3WLjr1uYnieyi2EOwkDcTE/WGhsY5PnU1aGg1u/CWDc8e
ohYL37frTSIAWt8d85dr3oA+QpGuLGYKPhjSt09sYBlEdAVTYi4PdNHSIkRGXDsV
nQfHobii9g==
-----END CERTIFICATE-----
]]

-- cakey is the key that belongs to the cacert above.
local cakey = [[
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCelWZByPQHb/pVW/Fp0PIlLwOClbNao3g6PfdiF0gMe7d3cXL4
3vjE+Q/1XpxNsFCdq/D9RdTh+4rcEJbBTMw3txbcjS1P5OUhKf2TZMsaKCbU1A/u
tO5VsQVejXoVxOxdUZGG+JEMXadvzoHdXpVaDxx44rZTIHTVqHIB1e7S7wIDAQAB
AoGBAJgBtqHKIHdck4Tse6wlN2YC+YdbPS7dUGnracwhatNkZwjbuwvolmYgInbc
+E/TeIKaBIaRQCxY89JbKFYi6f/fZHDpNFS9cTMBjPPkzRD+HkC6T3nt1BF6tKul
T0n4W0R+bJakqPxl3dxAKlsNYKwawb6RSsRrMr48/H1SVAtJAkEAzko5BF0Zd71m
pEjOZrLX4F9UO7OkBocFF58FDp1Ft31k5huZabtqutZ+t+qDQGAl2vGFbUE0xrdd
GMve0iuBmwJBAMTMOuST5EeIfxlHBtDyHrUL8R4GuD3lPL3fSr1FOvy3TkkWBJHQ
ooyog+ndCXy3h+s6/3GfEeFtZUMX5yN2Yz0CQD4alkO8C3jC6m23BXxhhyAjUuaO
VGkqqNvNoeYebuiotYGY+XydUaph/NA9p7nvuDXL1FFp+guBFGPsrG41btUCQQCk
o+exSzjzz3Hlh9JgA+9Er9Tstdp1jc6fWquAZObQfdp0soLoKo+S9XhGsrE5MaH4
XcdPGzEuUwMgemLY/DZRAkEAlNOCnvza3pVYcwv/li5E8nRImbbCP3Cc6f8QSgSg
hmRpR/XvnuXQcYH+tAq5Pq7+BcgMCXTYpFZH58REwH0riQ==
-----END RSA PRIVATE KEY-----
]]

-- it's wrong cause it does not match the cakey.
local wrong_cacert = [[
-----BEGIN CERTIFICATE-----
MIICnjCCAgegAwIBAgIJAKheTApDklUeMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNV
BAYTAk5MMSAwHgYDVQQKDBdXaXRtb25kIFNlY3VyZSBTb2Z0d2FyZTEdMBsGA1UE
CwwUV2l0bW9uZCBFY2NlbnRyaWMgQ0ExGDAWBgNVBAMMD2VjY2Eud2l0bW9uZC5u
bDAeFw0xMjA4MDQxNDM1NTJaFw0yMjA4MDIxNDM1NTJaMGgxCzAJBgNVBAYTAk5M
MSAwHgYDVQQKDBdXaXRtb25kIFNlY3VyZSBTb2Z0d2FyZTEdMBsGA1UECwwUV2l0
bW9uZCBFY2NlbnRyaWMgQ0ExGDAWBgNVBAMMD2VjY2Eud2l0bW9uZC5ubDCBnzAN
BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsoRDH1+uAx+KmkcsFbmLlxf5FNZlghzy
n954P1/bvRtFfHYR8s/UHpkSmo5fwTqf+kumr+ypdo1NUEdjV5wd0HjSvmjO/qLJ
hWJ66ht8a8muFPvEgSkrZfc8tKcL52GoqysrJo8XTI2ftNwsNJ+BnW4dzb2n7cAU
YSd4nG8+3O8CAwEAAaNQME4wHQYDVR0OBBYEFPoBVISGJ+LuXU6yQUbQ6HDCoE6m
MB8GA1UdIwQYMBaAFPoBVISGJ+LuXU6yQUbQ6HDCoE6mMAwGA1UdEwQFMAMBAf8w
DQYJKoZIhvcNAQEFBQADgYEAM4TrN2yfLajUFgKYM7f3xBIwO3jQBQGij/kGJuZk
b53guw66XTB7HhKHCFu9Sa1ySSPCpEKWhBG9YmNCPRr4nzjmCytHmNWwprR+L1H0
stYU8Sb3Gw+dw/ysOWRdHtVsqKND26ZLHVtEBqkgD7+d1BafXdqz/x4PdttY13Ct
nZg=
-----END CERTIFICATE-----
]]

local spkac = [[
MIIBOjCBpDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApfqLdp5Pffzs/RDDSThePsFcVi0kc5ciH7bmU348tc2eWUAZ6IKZBmHKq7YcArNADh9C9Rh5B7kpjxjzV2Ed6L/5jdE02ptiOQjWudEdv0S4kbudBu4MpWr1Lxyj5Xnk48zqwX3mYrIIpn2LEwdNCwtRo3R4fceXzLJZEcnQ6p8CAwEAARYAMA0GCSqGSIb3DQEBBAUAA4GBAHJZSdCF5yojbMV9lofr7J0aNsesHDhkA11YVRzojIRx9tZ6SuiOacHEXP9DgZyeVcWxwTvvE/GX2nAvFeGzQsZS83ZGsc0xlOb6C/jK5FbrLoNYT+nH0tE0qc8rXwM1gj4TcMh1gdeTBrcYbKa4vdYfwltG4jbAA8I+hGFbLXSH
]]

plan(37)

local ecca_lib = require 'ecca_lib';
if not ecca_lib then
    skip_all "no ecca_lib"
end

--------------------------------
-- Test the SIGN_CSR function
--------------------------------

-- Check to see that it wants parameters
error_like(ecca_lib.sign_csr, {nil}, "bad argument #1", "Must have a private key as first parameter")

-- Check parameter parsing for cakey
error_like(ecca_lib.sign_csr, {"not a pem private key"}, "Error decoding private key", "Must have a valid pem encoded private key as first parameter")

error_like(ecca_lib.sign_csr, {[[
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCelWZByPQHb/pVW/Fp0
]]}, "Error decoding private key", "Must have a complete and valid pem encoded private key as first parameter")

-- test valid cakey. It should complain about arg 2.
error_like(ecca_lib.sign_csr, {cakey, nil}, "bad argument #2", "Cakey is valid.")

-- Test parameter parsing for cacert
error_like(ecca_lib.sign_csr, {cakey, "not a pem certificate"}, "Error decoding certificate", "Must have a valid pem encoded certificate as second parameter")

error_like(ecca_lib.sign_csr, {cakey, [[
-----BEGIN CERTIFICATE-----
MIICozCCAgygAwIBAgIJAKheTApDkl
]]}, "Error decoding certificate", "Must have a complete and valid pem encoded certificate as second parameter")

-- test valid cakey and cacert. It should complain about arg 3.
error_like(ecca_lib.sign_csr, {cakey, cacert, nil}, "bad argument #3", "Cakey and Cacert match")

-- test wrong cacert and cakey combination
error_like(ecca_lib.sign_csr, {cakey, wrong_cacert, nil}, "CA certificate and CA private key do not match!", "Verify that Cakey and Cacert do not match.")

-- test correct operation
cert, text = ecca_lib.sign_csr(cakey, cacert, csr)
like(cert, "-----BEGIN CERTIFICATE-----", "Certificate is created")
like(text, "Issuer: C=NL, O=Witmond Secure Software, OU=Witmond Eccentric CA, CN=sub1.ecca.witmond.nl", "Certificate is signed with correct CA")
like(text, "Subject: CN=username", "Certificate has correct subject")

--print("cert is: ", text, cert)


----------------------------------
-- Test the SIGN_CN_KEY function
----------------------------------

-- Check to see that it wants parameters
error_like(ecca_lib.sign_cn_key, {nil}, "bad argument #1", "Must have a private key as first parameter")

-- Check parameter parsing for cakey
error_like(ecca_lib.sign_csr, {"not a pem private key"}, "Error decoding private key", "Must have a valid pem encoded private key as first parameter")

error_like(ecca_lib.sign_cn_key, {[[
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCelWZByPQHb/pVW/Fp0
]]}, "Error decoding private key", "Must have a complete and valid pem encoded private key as first parameter")

-- test valid cakey. It should complain about arg 2.
error_like(ecca_lib.sign_cn_key, {cakey, nil}, "bad argument #2", "Cakey is valid.")

-- Test parameter parsing for cacert
error_like(ecca_lib.sign_cn_key, {cakey, "not a pem certificate"}, "Error decoding certificate", "Must have a valid pem encoded certificate as second parameter")

error_like(ecca_lib.sign_cn_key, {cakey, [[
-----BEGIN CERTIFICATE-----
MIICozCCAgygAwIBAgIJAKheTApDkl
]]}, "Error decoding certificate", "Must have a complete and valid pem encoded certificate as second parameter")

-- test valid cakey and cacert. It should complain about arg 3.
-- this also tests the missing cn parameter
error_like(ecca_lib.sign_cn_key, {cakey, cacert, nil, nil}, "bad argument #3", "Cakey and Cacert match")

-- test missing pubkey. It should complain about arg 4.
error_like(ecca_lib.sign_cn_key, {cakey, cacert, cn, nil}, "bad argument #4", "Missing pubkey")

-- test invalid pubkey
error_like(ecca_lib.sign_cn_key, {cakey, cacert, cn, [[
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ
]]
}, "Error decoding public key", "Reject invalidly encoded public key")


-- test wrong cacert and cakey combination
error_like(ecca_lib.sign_cn_key, {cakey, wrong_cacert, nil, nil}, "CA certificate and CA private key do not match!", "Verify that Cakey and Cacert do not match.")

-- test correct operation
cert, text = ecca_lib.sign_cn_key(cakey, cacert, cn, pubkey)
like(cert, "-----BEGIN CERTIFICATE-----", "Certificate is created")
like(text, "Issuer: C=NL, O=Witmond Secure Software, OU=Witmond Eccentric CA, CN=sub1.ecca.witmond.nl", "Certificate is signed with correct CA")
like(text, "Subject: CN=username", "Certificate has correct subject")

--print("cert is: ", text, cert)

------------------------------------
-- Test the SIGN_CN_SPKAC function
------------------------------------

-- Check to see that it wants parameters
error_like(ecca_lib.sign_cn_spkac, {nil}, "bad argument #1", "Must have a private key as first parameter")

-- Check parameter parsing for cakey
error_like(ecca_lib.sign_cn_spkac, {"not a pem private key"}, "Error decoding private key", "Must have a valid pem encoded private key as first parameter")

error_like(ecca_lib.sign_cn_spkac, {[[
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCelWZByPQHb/pVW/Fp0
]]}, "Error decoding private key", "Must have a complete and valid pem encoded private key as first parameter")

-- test valid cakey. It should complain about arg 2.
error_like(ecca_lib.sign_cn_spkac, {cakey, nil}, "bad argument #2", "Cakey is valid.")

-- Test parameter parsing for cacert
error_like(ecca_lib.sign_cn_spkac, {cakey, "not a pem certificate"}, "Error decoding certificate", "Must have a valid pem encoded certificate as second parameter")

error_like(ecca_lib.sign_cn_spkac, {cakey, [[
-----BEGIN CERTIFICATE-----
MIICozCCAgygAwIBAgIJAKheTApDkl
]]}, "Error decoding certificate", "Must have a complete and valid pem encoded certificate as second parameter")

-- test valid cakey and cacert. It should complain about arg 3.
-- this also tests the missing cn parameter
error_like(ecca_lib.sign_cn_spkac, {cakey, cacert, nil, nil}, "bad argument #3", "Cakey and Cacert match")

-- test missing spkac. It should complain about arg 4.
error_like(ecca_lib.sign_cn_spkac, {cakey, cacert, cn, nil}, "bad argument #4", "Missing spkac")

-- test invalid spkac
error_like(ecca_lib.sign_cn_spkac, {cakey, cacert, cn, [[
MIIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ
]]
}, "Cannot decode Public Key data. Please provide a valid SPKAC structure.", "Reject invalid encoded spkac structure")


-- test wrong cacert and cakey combination
error_like(ecca_lib.sign_cn_spkac, {cakey, wrong_cacert, nil, nil}, "CA certificate and CA private key do not match!", "Verify that Cakey and Cacert do not match.")

-- test correct operation
cert, text = ecca_lib.sign_cn_spkac(cakey, cacert, cn, spkac)
like(cert, "-----BEGIN CERTIFICATE-----", "Certificate is created")
like(text, "Issuer: C=NL, O=Witmond Secure Software, OU=Witmond Eccentric CA, CN=sub1.ecca.witmond.nl", "Certificate is signed with correct CA")
like(text, "Subject: CN=username", "Certificate has correct subject")

--print("cert is: ", text, cert)

