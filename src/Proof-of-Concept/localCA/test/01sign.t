#!/usr/bin/env lua

require 'Test.More'
local https = require("ssl.https")

plan(8)

-- utility to execute command with input and collect stdout
function backtick(cmd, input)
   local pipe = assert(io.popen(cmd, "r+"))
   --io.stderr:write("backtick command: ", cmd, "\ninput is: ", (input or "(nil)"), "\n")
   if input then 
      pipe:write(input)
      pipe:flush()
   end

   local result = pipe:read("*all")
   pipe:close()
   return result
end

-- call (url) and capture the body.
function call (url, post_body) 
   local result_table = {}
   local default = { sink = ltn12.sink.table(result_table), }
   -- set efault settings
   for k, v in pairs(default) do 
      url[k] = url[k] or v
   end
   
   -- send the content body and header
   if post_body then
      local headers = url.headers or {}
      headers["content-length"] = string.len(post_body)
      url.headers = headers
      url.source = ltn12.source.string(post_body)
   end

   local res, code, headers, status = https.request(url)
   return { 
      res = res,
      body = table.concat(result_table),
      code = code,
      headers = headers,
      status = status, }
end

function url_encode(str)
   if (str) then
      str = string.gsub (str, "\n", "\r\n")
      str = string.gsub (str, "([^%w ])",
			 function (c) return string.format ("%%%02X", string.byte(c)) end)
      str = string.gsub (str, " ", "+")
   end
   return str
end

-- create new client identifiers every time 
CLIENT_KEY = os.tmpname()
CLIENT_CSR = os.tmpname()
CLIENT_CERT = os.tmpname()

-- generate a random string, use find to take the basename of the filename.
-- users are called lua_XYZZY
_, _, CN = string.find(CLIENT_KEY, "/([^/]+)$")

-- check if it is still available
local response = call({url = "https://localhost:7444/check-nickname-available?nickname=" .. CN,
			 verify = { "none" },
		      })
is(response.code, 404, "nickname is available")

-- create a CSR
req_cmd = "openssl req -new -newkey rsa:1024 -nodes -keyout " .. CLIENT_KEY  .. " -out " .. CLIENT_CSR .. " -subj /CN=" .. CN
_ = backtick(req_cmd)

-- check it
test_cmd = "openssl req -noout -subject -in " .. CLIENT_CSR
out = backtick(test_cmd)
like(out, "^subject=/CN=" .. CN, "certificate request is created")

--read it
local c = assert(io.open(CLIENT_CSR))
csr = c:read("*all")
c:close()

-- send the CSR in the body to the CA-website for registering
local response = call({url = "https://localhost:7444/register",
			 verify = { "none" },
			 method = "POST",
		      },
		      "csr=" .. url_encode(csr))
is(response.code, 201, "CA server signed our request")
local cl_cert_text = response.body
local _, _, cl_cert = string.find(cl_cert_text, "(BEGIN CERTIFICATE.*END CERTIFICATE)")

-- test for valid contents in the cert-file
local fh = assert(io.open(CLIENT_CERT, "w"))
fh:write(cl_cert_text) -- the whole shebang
fh:close()

test_cmd = "openssl x509 -noout -subject -in " .. CLIENT_CERT
out = backtick(test_cmd)
like(out, "^subject= /CN=" .. CN, "certificate is valid")


-- we can only certify each CN once, 
-- check if it is taken
local response = call({url = "https://localhost:7444/check-nickname-available?nickname=" .. CN,
			 verify = { "none" },
		      })
is(response.code, 200, "nickname is registered ok")
ok(string.find(response.body, cl_cert, 1, true), "It returns the correct certificate")

-- send the request again and expect an error
local response = call({url = "https://localhost:7444/register",
			 verify = { "none" },
			 method = "POST",
		      },
		      "csr=" .. url_encode(csr))
is(response.code, 403, "server rejects same request")
like(response.body, "Username: " .. CN .. " is already taken, please choose another.", "Reject message ok")

-- cleanup
os.remove(CLIENT_KEY)
os.remove(CLIENT_CSR)
os.remove(CLIENT_CERT)

--end
