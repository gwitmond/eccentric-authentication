#!/usr/bin/env lua

-- make sure ecca_lib is installed
ecca_lib = require 'ecca_lib'

-- these should be set at nginx.conf level.
CACERT=assert(os.getenv("CACERT"), "Missing CACERT configuration parameter")
CAKEY =assert(os.getenv("CAKEY"),  "Missing CAKEY configuration parameter")


-- Main
-- Register a username, if unique

function register_spkac() 
   ngx.req.read_body()
   local args = ngx.req.get_post_args()
   local cn = args.cn
   local spkac = args.spkac

   -- primitive input validation
   if cn == nil then
      ngx.status = ngx.HTTP_BAD_REQUEST -- 400
      ngx.say("There is no username! Please specify one.")
      ngx.exit(0)
   end

   if spkac == nil then
      ngx.status = ngx.HTTP_BAD_REQUEST -- 400
      ngx.say("There is no Public Key given! Please generate one.")
      ngx.exit(0)
   end
   -- change the line based layout from firefox into a single line for openssl parsing
   spkac = string.gsub(spkac, "[\r\n]", "")

   io.stderr:write("spkca is ", spkac)
   -- validate uniqueness, before creating a certificate
   local res = ngx.location.capture("/check-nickname-available", {args = {nickname = cn}})
   if res.status == 200 then
      ngx.status = ngx.HTTP_FORBIDDEN -- 403
      ngx.say("Username: ", cn, " is already taken, please choose another.\n", res.body)
      ngx.exit(0)

   elseif res.status == 404 then  -- 404 means cn is available, proceed to create a certificate      
      -- read cakey
      local k = assert(io.open(CAKEY, "r"))
      local cakey = k:read("*all")
      k:close()

      -- read cacert
      local c = assert(io.open(CACERT, "r"))
      local cacert = c:read("*all")
      c:close()

      -- generate certificate!
      cl_cert, text = ecca_lib.sign_cn_spkac(cakey, cacert, cn, spkac)
   
      if cl_cert then
	 -- store the pem-cert under the CN
	 local res2 = ngx.location.capture("/memcacheDB-cn", { 
					      method = ngx.HTTP_POST, body = cl_cert,
					      args = { 
						 key   = cn,
					      }
					   })
	 -- TODO: handle errors from memcache store.
	 io.stderr:write("certificate created. Storing gave: ", res2.status, res2.body)

	 -- TODO: encode it for the specific browser (is that needed?)
	 ngx.header["Content-Type"] = 'application/x-x509-user-cert'
	 ngx.status = res2.status; -- we return errorcode of memcacheDB: 201, 404...
	 ngx.say([[
<html><head><title>Certified</title></head>
<body>
<h1>Certified</h1>
<p>Your request was accepted and your chosen username is now yours.
<br>Please find the certificate below and follow these instructions to install it into your browser.
<ol><li>First create a file format that is usable by the browsers:
<ol><li>Save this page into a file cc/cert.pem
<li>run: openssl pkcs12 -export -in cert.pem -inkey private-key.pem -name "Username at <Sitename>" -out cert.p12 
<li>Specify a password to encrypt the key. Or press Enter twice to leave it unencrypted.
</li></ol>
<li>Import the cert.p12 into Firefox:
<ol><li>Open the Firefox Preferences -> Advanced -> Encryption -> View Certificates
<li>Press "Import", select the file cert.p12
<li>Enter the import password you've created in the previous step. (or press enter twice)
<li>Finished.
<ol>
		       
		 ]])
	 ngx.say("<pre>", text, "\n", cl_cert, "</pre>\nstored or not: ", res2.status ," ", res2.body)
	 ngx.exit(0)
      else
	 -- Error creating certificate
	 ngx.status = 500
	 nginx.say("Certification failed ", text)
	 ngx.exit(0)
      end
   end
end

-- Just call it.
register_spkac()