#!/usr/bin/env lua

-- these should be set at nginx.conf level.
SUBCA="/Users/guido/eccentric-authentication/src/Proof-of-Concept/localCA/subCA"
SUBCA_CONFIG=SUBCA .. "/openssl-subca.cnf"

local openssl = require 'openssl'

-- utility to execute command with input and collect stdout
function backtick(cmd, input)
   io.stderr:write("backtick command: ", cmd, "\ninput is: ", (input or "(nil)"), "\n")
   local t = {}
   local pipe = assert(io.popen(cmd, "r+"))
   if input then
      pipe:write(input)
      --pipe:flush()
   end
   local line = pipe:read("*line")
   while line do
      table.insert(t, line)
      line = pipe:read("*line")
   end
   pipe:close()
   io.stderr:write("backtick read: " .. table.concat(t) .. "\n")
   return t
end

-- parse_dn("/CN=name/L=place") -> { CN = "name", L = "place" }
-- note, TODO: parsing ends on embedded / characters in a field.
function parse_dn(line)
   local fields = {}
   for name, value in string.gfind(line, "/([A-Z]+)=([^/]+)") do
      fields[name] = value
   end
   return fields
end

-- Main 
-- Register a username, if still unique.

function main() 
   ngx.req.read_body()
   local args = ngx.req.get_post_args()
   local csr = args.csr
   
   -- retrieve the username from the csr,
   local req_cmd = "openssl req -subject -noout"
   local dn = backtick(req_cmd, csr)
   local fields = parse_dn(dn[1])  -- only parse first line.
   local cn = fields.CN
   
   -- validate uniqueness, before creating a certificate 
   -- as lookup is cheaper than generating it first

   local res = ngx.location.capture("/check-nickname-available", {args = {nickname = cn}})
   if res.status == 200 then
      ngx.say("Username: ", cn, " is already taken, please choose another.")
      ngx.exit(200)

   elseif res.status == 404 then  -- 404 means cn is available, proceed to create a certificate
      -- write csr to file for openssl ca (it does not listen to stdin)
      local csr_file = os.tmpname()
      local fh = io.open(csr_file, "w")
      fh:write(csr)
      fh:close()
      
      -- generate certificate,
      local ca_cmd = "openssl ca -config " .. SUBCA_CONFIG  .. " -batch -in " .. csr_file
      local cert = backtick(ca_cmd, csr)
      
      local res2 = ngx.location.capture("/memcacheDB-cn", { method=ngx.HTTP_POST, 
					   args = { cmd = set,
					      key   = cn,
					      body = table.concat(cert)}})
      io.stderr:write("memcache store gave:", res2.status, "\n", res2.body, "\n")
      -- encode it for the specific browser (todo: is that needed?)
      ngx.say("your CN: <code>", cn, "</code> is registered.<p>please see the cert:\n<br><pre>", table.concat(cert, "\n"), "</pre>")
      ngx.exit(200)
   end
end

main()