#!/usr/bin/env lua

require 'Test.More'
local https = require("ssl.https")

-- Globals
SERVER_CERT = "../server-cert.pem"
SERVER_KEY  = "../server-key.pem"

-- call (url) and capture the body.
function call (url, post_body) 
   local result_table = {}
   local def = { sink = ltn12.sink.table(result_table), }
   -- Default settings
   for k, v in pairs(def) do 
      url[k] = url[k] or v
   end

   local res, code, headers, status = https.request(url, post_body)
   return { 
      res = res,
      body = table.concat(result_table),
      code = code,
      headers = headers,
      status = status, }
end


plan(9)

local response = call({ url = "https://localhost:7443/index.html"})
is(response.code, 200, "server is alive")


-- check out if server has the correct server certificate
local response = call({url = "https://localhost:7443/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
		      })
is(response.code, 200, "server has correct server certififate")


-- check out if server requires client certificate for authenticated part, while we provice none
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
		      })
is(response.code, 401, "server has correctly rejected access to authenticated part which we didn't have a certificate for")
like(response.body, "401 -", "got 401-error page")

-- check out if server reject our wrong client certificate for authenticated part
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
-- utility to execute command with input and collect stdout
function backtick(cmd, input)
   local pipe = assert(io.popen(cmd, "r+"))
   if input then 
      pipe:write(input)
      pipe:flush()
   end

   local t = {}
   local line = pipe:read("*line")
   while line do
      table.insert(t, line)
      line = pipe:read("*line")
   end
   pipe:close()
   return t
end

-- create new client identifiers every time 
CLIENT_KEY = -- os.tmpname() -- 
   "private-key.pem"
CLIENT_CSR = -- os.tmpname() -- 
   "certificate-request.pem"
CLIENT_CERT = -- os.tmpname() -- 
   "certificate.pem"

-- generate a random string, use find to take the basename of the filename.
-- users are called lua_XYZZY
_, _, CN=string.find(os.tmpname(), "/([^/]+)$")

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
out = backtick(test_cmd)
like(out[1], "^subject= /CN=" .. CN, "certificate is valid")

-- now test that certificate at the site
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer" },
			 cafile = SERVER_CERT,
			 certificate = CLIENT_CERT,
			 key         = CLIENT_KEY,
		      })
is(response.code, 200, "server grants access to authenticated part with our correct certificate and private key")
