#!/usr/bin/env lua

require 'Test.More'
local https = require("ssl.https")

-- Globals
SERVER_CERT = "../server-cert.pem"
SERVER_KEY  = "../server-key.pem"

-- call (url) and capture the body.
function call (url) 
   local result_table = {}
   local def = { sink = ltn12.sink.table(result_table), }
   -- Default settings
   for k, v in pairs(def) do 
      url[k] = url[k] or v
   end

   local res, code, headers, status = https.request(url)
   return { 
      res = res,
      body = table.concat(result_table),
      code = code,
      headers = headers,
      status = status, }
end


plan(4)

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

