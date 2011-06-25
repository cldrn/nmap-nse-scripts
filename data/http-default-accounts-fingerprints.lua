---
-- http-default-accounts-fingerprints.lua
-- This file contains fingerprint data for http-default-accounts.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
-- * <code>category</code> - Category
-- * <code>login_username</code> - Default username
-- * <code>login_password</code> - Default password
-- * <code>paths</code> - Paths table containing the possible location of the target
-- * <code>login_check</code> - Login function of the target
---

fingerprints = {}

---
--WEB
---
table.insert(fingerprints, {
  name = "Cacti",
  category = "web",
  paths = {
    {path = "/cacti/"},
    {path = "/monitoring/cacti/"}
  },
  login_username = "admin",
  login_password = "admin",
  login_check = function (host, port, path, user, pass)
    local req = http.post(host, port, path.."index.php", {no_cache=true}, nil, {action="login", login_username=user, login_password=pass})
    if not(http.response_contains(req, 'Invalid User Name/Password')) then
      return true
    end
    return false
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/tomcat/manager/html/"}
  },
  login_username = "tomcat",
  login_password = "tomcat",
  login_check = function (host, port, path, user, pass)
    local credentials = {username = user, password = pass}
    local req = http.get(host, port, path, {no_cache=true, auth=credentials})
    if req.status ~= 401 and req.status ~= 403 then
      return true
    end
    return false
  end
})


---
--ROUTERS
---

