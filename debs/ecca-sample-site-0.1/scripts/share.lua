#!/usr/bin/env lua

require("scripts/util")
json = require 'json'

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