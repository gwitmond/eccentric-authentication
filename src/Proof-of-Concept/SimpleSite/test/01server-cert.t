#!/usr/bin/env lua

require 'Test.More'
local https = require("ssl.https")

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

plan(1)

local response = call({ url = "https://localhost:7443/index.html"})
is(response.code, 200, "server is alive")


-- check out if server has the correct server certificate
local response = call({url = "https://localhost:7443/index.html",
			 verify = { "peer"},
			 cafile = "../cert.pem",
		      })
is(response.code, 200, "server has correct server certififate")


-- check out if server requires client certificate for authenticated part, while we provice none
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer"},
			 cafile = "../cert.pem",
		      })
is(response.code, 401, "server has correctly rejected access to authenticated part which we didn't have a certificate for")


-- check out if server reject our wrong client certificate for authenticated part
local response = call({url = "https://localhost:7443/secure/index.html",
			 verify = { "peer"},
			 cafile = "../cert.pem",
			 certificate = "../cert.pem", -- how more wrong can you get
			 key = "../cert.key",         -- with the servers' cert and key
		      })
is(response.code, 400, "server has correctly rejected access to authenticated part with our wrong certificate and private key")
-- Nginx server gives a 400-access violation, probably to be nice to the world. I want a 403-forbidden.
-- It does give the /495.html page, so I consider it good enough (for now).

