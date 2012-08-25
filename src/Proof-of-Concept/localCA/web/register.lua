#!/usr/bin/env lua

package.cpath = "ca-lib/?.so;;" -- TODO: set cpath in nginx.conf
require 'ecca_lib'

-- these should be set at nginx.conf level.
SUBCA="/Users/guido/eccentric-authentication/src/Proof-of-Concept/localCA/subCA"
CACERT= SUBCA .. "/subcacert.pem"
CAKEY=  SUBCA .. "/private/subcakey.pem"

-- Main
-- Register a username, if unique

function register() 
   ngx.req.read_body()
   local args = ngx.req.get_post_args()
   local csr = args.csr
   if csr == nil then
      ngx.status = ngx.HTTP_BAD_REQUEST -- 400
      ngx.say("There is no csr attribute in the post parameters.")
      ngx.exit()
   end

   -- retrieve the username from the csr,
   local csr_data = ecca_lib.parse_csr(csr)
   local cn = csr_data.CN
   if cn == nil then
      ngx.status = ngx.HTTP_BAD_REQUEST -- 400
      ngx.say("There is no CN in the certificate. Please set -subj field (correctly).")
      ngx.exit(0)
   end

   -- validate uniqueness, before creating a certificate
   local res = ngx.location.capture("/check-nickname-available", {args = {nickname = cn}})
   if res.status == 200 then
      ngx.status = ngx.HTTP_FORBIDDEN -- 403
      ngx.say("Username: ", cn, " is already taken, please choose another.", res.body)
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
      cl_cert, text = ecca_lib.sign_csr(cakey, cacert, csr)
   
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
	 ngx.status = res2.status; -- we return errorcode of memcacheDB: 201, 404...
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
register()