#!/usr/bin/env lua

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