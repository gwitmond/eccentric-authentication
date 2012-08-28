#!/usr/bin/env lua

-- Tests to see if the web server is configured correctly with the Certificates.
-- We test both the server certificates as well as the client certificates

dofile("util.lua")
require 'Test.More'

-- Globals
SERVER_CERT = "../demoCA/server-cert.pem"
SERVER_KEY  = "../demoCA/server-key.pem"


plan(9)

local response = call({ url = "https://localhost:7443/index.html"})
is(response.code, 200, "server is alive")


-- check out if server has the correct server certificate
local response = call({url = "https://localhost:7443/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
		      })
is(response.code, 200, "server has correct server certificate")


-- check out if server requires client certificate for authenticated part, while we provice none
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
		      })
is(response.code, 401, "server has correctly rejected access to authenticated part which we didn't have a certificate for")
like(response.body, "401 -", "got 401-error page")

-- check out if server rejects our wrong client certificate for authenticated part
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
			 certificate = SERVER_CERT, -- how more wrong can you get
			 key         = SERVER_KEY,  -- with the servers' cert and key
		      })
is(response.code, 400, "server has correctly rejected access to authenticated part with our wrong certificate and private key")
-- Nginx server gives a 400-access violation, probably to be nice to the world. I want a 403-forbidden.

like(response.body, "495 -", "got 495-error page")
-- It does give the /495.html page, so I consider it good enough (for now).

--------------------------------------------
-- Now test with a localCA signed signature
--------------------------------------------

CLIENT_KEY = os.tmpname() 
CLIENT_CSR = os.tmpname()
CLIENT_CERT = os.tmpname()
_, _, CN=string.find(CLIENT_KEY, "/([^/]+)$")  -- users are called lua_XYZZY

-- create a CSR
req_cmd = "openssl req -new -newkey rsa:1024 -nodes -keyout " .. CLIENT_KEY  .. " -out " .. CLIENT_CSR .. " -subj /CN=" .. CN
ok(os.execute(req_cmd), "create private key and CSR")

-- sign the CSR with the CA directly (not via localCA website) so we can prove that this site accepts the localCA.
CA_HOME = "/Users/guido/eccentric-authentication/src/Proof-of-Concept/localCA/subCA"
ca_cmd = "openssl ca -config " .. CA_HOME .."/openssl-subca.cnf -policy policy_ecca -batch -out " .. CLIENT_CERT .. " -in " .. CLIENT_CSR
out = backtick(ca_cmd)

-- Generating a certificate is fragile and does not return an error status code, nor easy to parse data on stdout.
-- therefore, test for valid contents in the cert-file
test_cmd = "openssl x509 -noout -subject -in " .. CLIENT_CERT
subj = backtick(test_cmd)
like(subj, "^subject= /CN=" .. CN, "certificate is valid")

-- now test that certificate at the site
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
			 certificate = CLIENT_CERT,
			 key         = CLIENT_KEY,
		      })
is(response.code, 200, "server grants access to authenticated part with our correct certificate and private key")

-- cleanup
os.remove(CLIENT_KEY)
os.remove(CLIENT_CSR)
os.remove(CLIENT_CERT)

-- end