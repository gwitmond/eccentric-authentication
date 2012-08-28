#!/usr/bin/env lua

dofile("util.lua")
require 'Test.More'

-- Globals
SERVER_CERT = "../demoCA/server-cert.pem"

-- Ecca server certificate (that signs the CSR-request)
ECCA_SERVER_CERT = "../../localCA/web/demoCA/server-cert.pem"

-- create new client identifiers every time
CLIENT_KEY = os.tmpname()
CLIENT_CSR = os.tmpname()
CLIENT_CERT = os.tmpname()
_, _, CN = string.find(CLIENT_KEY, "/([^/]+)$")  -- users are called lua_XYZZY


plan(4)

-- create a CSR
req_cmd = "openssl req -new -newkey rsa:1024 -nodes -keyout " .. CLIENT_KEY  .. " -out " .. CLIENT_CSR .. " -subj /CN=" .. CN
ok(os.execute(req_cmd), "create private key and CSR")

-- read it from disk
local fh = assert(io.open(CLIENT_CSR, "r"))
local csr = fh:read("*all")
fh:close()

-- send it to the localCA to get signed
local response = call({url = "https://localhost:7444/register",
                   	 verify = { "peer" },
			 cafile = ECCA_SERVER_CERT,
                         method = "POST",
                      },
                      "csr=" .. url_encode(csr))
is(response.code, 201, "CA server signed our request")

-- test for valid contents in the cert-file
local fh = assert(io.open(CLIENT_CERT, "w"))
fh:write(response.body)
fh:close()

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

--end