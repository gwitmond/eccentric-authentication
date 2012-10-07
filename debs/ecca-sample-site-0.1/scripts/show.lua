#!/usr/bin/env lua

require("scripts/util")
json = require 'json'

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
