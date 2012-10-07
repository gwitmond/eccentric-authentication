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

function show_favorite_numbers()
   local template = ngx.location.capture("/template/show.template");   
   local rows = ""

   local numbers = db_read("numbers")
   if #numbers >= 1 then
      local t = {}
      for _, value in ipairs(numbers) do
	 local str = fill_template ([[<tr><td>__NAME__</td><td>__NUMBER__</td></tr>]],
				    { NAME = value.name, NUMBER = value.number })
	 table.insert(t, str)
      end
      rows = table.concat(t, "\n")
   else
      rows = "<tr><td colspan='2'>No favorite numbers. Be the first one to register and share your number</td></tr>"
   end

   local html = fill_template(template.body, {ROWS = rows})
   ngx.say(html)
end


-- just call it
show_favorite_numbers()
