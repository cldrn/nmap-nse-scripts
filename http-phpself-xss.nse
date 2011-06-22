description = [[
Crawls a web server looking for PHP files vulnerable to PHP_SELF cross site scripting vulnerabilities.

This script crawls the webserver to create a list of PHP files and then sends an attack vector/probe to all of them to identify PHP_SELF cross site scripting vulnerabilities.
PHP_SELF XSS refers to cross site scripting vulnerabilities caused by the lack of sanitation of the variable <code>$_SERVER["PHP_SELF"]</code> in PHP scripts. This variable is
commonly used in php scripts with forms and a lot of developers out there think it's safe to print it without escaping it first.

Examples of Cross Site Scripting vulnerabilities in the variable $_SERVER[PHP_SELF]:
*http://www.securityfocus.com/bid/37351
*http://software-security.sans.org/blog/2011/05/02/spot-vuln-percentage

The attack vector/probe used is: <code>/'"/><script>alert(1)</script></code>
You may test this script against http://calder0n.com/sillyapp/
]]

---
-- @usage
-- nmap -p80 --script http-phpself-xss --script-args 'http-phpself-xss.path=/sillyapp/' <host/ip>
-- It's important you don't forget the last / if you're setting a path
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-phpself-xss: Possible PHPSELF XSS: http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
-- |_Possible PHPSELF XSS: http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
---

author = "Paulino Calderon"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

require "http"
require "shortport"
require "stdnse"

portrule = shortport.http

local DEFAULT_PATH = "/"

local OPT_PATH = stdnse.get_script_args("http-phpself-xss.path") or DEFAULT_PATH

-- PHP_SELF Attack vector
local PHP_SELF_PROBE = '/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E'

--locals holding unvisited and visited links
local links_list = {}
local visited_links = {}
--Checks if URL is an absolute address
--@param url URL String
--@return True if "http://" is found
local function is_url_absolute(url)
  if string.find(url, "http://") then
    return true
  else
    return false
  end
end

--Checks if given string is a relative url
--@param url URL String
--@return True if url is a relative url
local function is_url_relative(url)
  if is_url_absolute(url) then
    return false
  end
  return true
end

--Returns the url including the script name without parameters.
--@param uri URL String
--@return URL without parameters
local function remove_query(uri)
  local url_frags, abs_url
  url_frags = url.parse(uri)
  if url_frags.scheme and url_frags.authority and url_frags.path then
    abs_url = url_frags.scheme.."://"..url_frags.authority..url_frags.path
  else
    abs_url = uri
  end
  return abs_url
end

--Checks if link is anchored ()
--Example: "#linkPointingInsideOfDocument"
--@param url URL String
--@return True if url is an anchored link
local function is_link_anchored(url)
  if string.sub(url, 1, 1) == "#" then
    return true
  end
  return false
end

--Checks if link is local.
--@param url_parts
--@param host
--@return True if link is local
local function is_link_local(url_parts, host)
  if url_parts.authority and
    not(url_parts.authority == stdnse.get_hostname(host) or
        url_parts.authority == "www."..stdnse.get_hostname(host)) then
    return false
  end

  return true
end

--Checks if link is malformed
--This function looks for:
--*Links that are too long
--*Links containing html code
--*Links with mailto tags
--
--@param url URL String
--@return True if link seems malformed
local function is_link_malformed(url)
  --check for links that are too long
  if string.len(url)>100 then
    return true
  end
  --check if brackets are found (indicating html code in link)
  if string.find(url, "[<>]") ~= nil then
    return true
  end
  --check for mailto tag
  if string.find(url, "mailto:") ~= nil then
    return true
  end
  --check if its a javascript action
  if string.find(url, "javascript:") ~= nil then
    return true
  end
  return false
end

--Checks if a link is crawable
--Criteria:
--*Must be a local link
--*Must be valid
--*Must be a link pointing outside a document
--@param uri URL String
--@param host Host table
--@return True if link meets criteria to be crawlable
local function is_link_crawlable(uri, host)
  local url_frags
  url_frags = url.parse(uri)
  if not(is_link_local(url_frags, host)) or is_link_anchored(uri) or is_link_malformed(uri) then
    return false
  end

  return true
end

--Parses the href attribute of the <a> tags inside the body
--@param body HTML Body
--@return Table of href links found in document
local function get_href_links(body)
  local href_links = {}

  body = string.lower(body)
  for l in string.gfind(body, 'href%s*=%s*[\'"](%s*[^"^\']+%s*)[\'"]') do
    table.insert(href_links, l)
  end

  return href_links
end

--Checks if url contains a blacklisted extension
--Maybe whitelist approach will work better
--@param ext Url extension
--@return True if the url contains a invalid extension
local function is_url_extension_blacklisted(ext)
  local banned_extensions = {".jpg",".png",".gif",".pdf",".doc",".ppt",".css",".js", ".rar", ".zip"}
  if ext then
    ext = string.lower(ext)
  end
  for _, banned_ext in pairs(banned_extensions) do
    if ext == banned_ext then
      return true
    end
  end

  return false
end

--Gets current path of URL
--@param url URL String
--@return Path string excluding OPT_PATH
local function get_current_path(uri, host)
  local base_path_frags, base_path_frags_num, path_frags, path_frags_num
  local current_path=""

  base_path_frags = url.parse_path("http://"..stdnse.get_hostname(host)..OPT_PATH)
  path_frags = url.parse_path(uri)
  base_path_frags_num = #base_path_frags
  path_frags_num = #path_frags
  for i = base_path_frags_num+1, path_frags_num-1, 1 do
    current_path = current_path..path_frags[i].."/"
  end

  return current_path
end

--Extracts file extension from URL
--@param uri URL String
--@return URL Extension
local function get_url_extension(uri)
  local page_ext, ext_offset, url_frags

  -- Parse file extension if available
  url_frags=url.parse(uri)
  if url_frags ~= nil then
    ext_offset = string.find(url_frags.path, "%.(.*)")
    if ext_offset ~= nil then
      page_ext = string.sub(url_frags.path, ext_offset)
    else
      page_ext = ""
    end
  end
 
  return page_ext
end

--Downloads a page and stores its information in the global table "links_list"
--@param host Host table
--@param port Port number
--@param url URL String
local function download_page(host, port, uri)
  local page_ext, ext_offset, page_resp

  -- Parse file extension if available
  page_ext = get_url_extension(uri)
-- Checks if url ext is blacklisted to save requests
  if is_url_extension_blacklisted(page_ext) then
    stdnse.print_debug(2, "Skipping %s", uri)
    return false
  else
    if uri ~= nil then
      stdnse.print_debug(2, "HTTP GET %s", uri)
    end
    --Append trailing path if missing
    if uri == "http://"..stdnse.get_hostname(host) or uri == "http://www."..stdnse.get_hostname(host) then
      uri = uri .. "/"
    end
    page_resp = http.get(host, port, uri)
  end
  --301,302,303 Redirections
  if page_resp.status == 301 or page_resp.status == 302 or page_resp.status == 303 then
    local new_target
    stdnse.print_debug(2, "HTTP REDIRECTION %s DETECTED", page_resp.status)
    if page_resp.header["location"] and not(visited_links[page_resp.header["location"]]) then
      new_target = page_resp.header["location"].."/"
      stdnse.print_debug(2, "Redirecting to: %s", new_target)
      -- Parse file extension if available
      page_ext = get_url_extension(new_target)
      -- Checks if url ext is blacklisted to minimize requests
      if is_url_extension_blacklisted(page_ext) then
        stdnse.print_debug(2, "Skipping %s", new_target)
        return false
      else
        return new_target
      end
     
    end
  end
  stdnse.print_debug(3, "%s returned:\n %s", uri, page_resp.body)
  -- Store page info in crawled list
  links_list[uri] = {["uri"]=uri, ["status"]=page_resp.status,
    ["checksum"]=stdnse.tohex(openssl.md5(page_resp.body)),
    ["ext"]=page_ext, ["type"]=page_resp.header["content-type"],
    ["content"]=page_resp.body}

  return true
end


--Crawls given URL until it find all local links
--@param uri URL
--@param options Options table
--@return Table of crawled pages and its information
local function crawl(uri, cur_path, options)
  local href_links, url_parts
  local hostname_str = stdnse.get_hostname(options["host"])

  stdnse.print_debug(2, "Crawling %s", uri)
  if not(is_link_crawlable(uri, options["host"])) then
    stdnse.print_debug(2, "Ignoring uri: %s", uri)
    return
  end
--Normalize urls by only using absolute urls
  if is_url_relative(uri) then
    uri = url.absolute("http://"..hostname_str..cur_path, uri)
  end

  uri = remove_query(uri)
  cur_path = get_current_path(uri, options["host"])
  --Download URI and extract links
  local download_page_res = download_page(options["host"], options["port"], uri)
  if not(download_page_res) then
    return
  -- if a redirect was detected then update current path 
  elseif type(download_page_res) == "string" then
    local new_target = remove_query(download_page_res)
    if visited_links[new_target] == nil then
      cur_path = get_current_path(new_target, options["host"])
      visited_links[new_target] = true
      crawl( new_target, cur_path, options)
    end
    return
  end
  href_links = get_href_links(links_list[uri]["content"])

--Iterate through link list
  for i, href_link in ipairs(href_links) do
    stdnse.print_debug(2, "HREF tag found: %s", href_link)
    if is_url_relative(href_link) then
      href_link = url.absolute("http://"..hostname_str.."/"..OPT_PATH..cur_path, href_link)
    end
    if href_link == "http://www."..hostname_str or href_link == "http://"..hostname_str then
      href_link = href_link .. "/"
    end
    --Recursive crawl when a link hasn't been visited
    if visited_links[href_link] == nil then
      visited_links[href_link]=true
      crawl( href_link, cur_path, options)
    end
  end

end

--Returns a list with all the crawled pages and its information
--@return Table of crawled pages
local function get_page_list()
  return links_list
end



--Checks if attack vector is in the response's body
--@param response Response table
--@return True if attack vector is found in response's body
local function check_probe_response(response)
  stdnse.print_debug(3, "Probe response:\n%s", response.body)
  if string.find(response.body, "'\"/><script>alert(1)</script>", 1, true) ~= nil then
    return true
  end
  return false
end

--Launches probe request
--@param host Hostname
--@param port Port number
--@param uri URL String
--@return True if page is vulnerable/attack vector was found in body
local function launch_probe(host, port, uri)
  local probe_response

  stdnse.print_debug(1, "HTTP GET %s%s", uri, PHP_SELF_PROBE)
  probe_response = http.get(host, port, uri .. PHP_SELF_PROBE)
  if check_probe_response(probe_response) then
    return true
  end
  return false
end

--[[
--MAIN
--]]
action = function(host, port)
  local options, pages, starting_uri
  local output_lns={}

  --Sets options and starts crawler
  options = {host = host, port = port}
  starting_uri = {uri = OPT_PATH}
  crawl(OPT_PATH, "", options)

  --Iterate through page list to find php files and send the attack vector
  pages = get_page_list()
  for _,pg in pairs(pages) do
    stdnse.print_debug(2, "Url: %s", pg["uri"])
    if pg["ext"] == ".php" and pg["status"] == 200 then
      if launch_probe(options["host"], options["port"], pg["uri"]) then
        output_lns[#output_lns + 1] = "PHPSELF Cross Site Scripting PoC: "..pg["uri"]..PHP_SELF_PROBE
      end
    end
  end

  if #output_lns > 0 then
    return stdnse.strjoin("\n", output_lns)
  end
end
