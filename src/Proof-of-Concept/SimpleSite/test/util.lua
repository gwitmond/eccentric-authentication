#!/usr/bin/env lua

-- Utility functions for testing.
local https = require("ssl.https")

-- call (url) and capture the body.
function call (url, post_body) 
   local result_table = {}
   local def = { sink = ltn12.sink.table(result_table), }
   -- Default settings
   for k, v in pairs(def) do 
      url[k] = url[k] or v
   end

   -- send the content body and header
   if post_body then
      local headers = url.headers or {}
      headers["content-length"] = string.len(post_body)
      url.headers = headers
      url.source = ltn12.source.string(post_body)
   end

   local res, code, headers, status = https.request(url, post_body)
   return { 
      res = res,
      body = table.concat(result_table),
      code = code,
      headers = headers,
      status = status, }
end


-- utility to execute command with input and collect stdout
function backtick(cmd, input)
   local pipe = assert(io.popen(cmd, "r+"))
   if input then 
      pipe:write(input)
      pipe:flush()
   end

   local result = pipe:read("*line")
   pipe:close()
   return result
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

