#!/usr/bin/env lua

json = require 'json'

-- helper functions for Eccentric Authentication

-- parse "/CN=foo/OU=bar/... " into { CN = "foo", OU="bar", ... }
function parse_dn(dn)
   local t = {}
   for k,v in string.gmatch(dn, "/(%a+)=([^/]+)") do
      t[k] = v
   end
   return t
end

-- Read a key from a persistant K/V store.
-- Decode the data from JSON
function db_read(key) 
   local res = ngx.location.capture("/memc", {args = {key = key}})
   if res.status == 200 then
      local v = json.decode(res.body)
      return v 
   else
      return {}
   end
end

-- Store a K/V pair in the persistant storage.
-- Accept only json-encodable data.
function db_store(key, value)
   return ngx.location.capture("/memc", { 
				  args = { key = key },
				  method = ngx.HTTP_PUT, 
				  body = json.encode(value)
			       })
end


-- Fill placeholders in a template.
-- Placeholders are __FOO__ with
-- two underscores at each end
-- and CAPS keys.
-- values is { FOO = "foo data", BAR = "bar data" }
function fill_template(template, values)
   return string.gsub(template, "__([A-Z]+)__", values)
end


function share_favorite_number()
   ngx.req.read_body()

   local dn=parse_dn(ngx.var.ssl_client_s_dn)
   local cn=dn.CN or "unknown"
   local userkey = "user " .. cn  -- make sure to tag the key to prevent /CN=numbers

   local prevnums = db_read(userkey)
   local previous = table.concat(prevnums, ", ")
   if previous == "" then previous = "none" end

   local args = ngx.req.get_post_args()
   local favnum = args["favorite-number"] or "foo" -- this fails the match and shows the form

   if not string.match(favnum, "^%d+$") then
      local template = ngx.location.capture("/template/share.template")
      local html = fill_template(template.body, { USER = cn, PREVIOUS = previous})
      ngx.say(html)
   else
      -- update the favorite numbers
      local numbers = db_read("numbers")
      table.insert(numbers, {name = cn, number = favnum})
      while #numbers > 10 do
	 table.remove(numbers, 1) -- remove oldest favorite number
      end
      db_store("numbers", numbers)

      -- add the favnum to the previous numbers of the user.
      table.insert(prevnums, favnum)
      db_store(userkey, prevnums)
      ngx.redirect("/show")
   end
end

-- just call it
share_favorite_number()