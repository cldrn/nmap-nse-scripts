<?php
if(isset($_POST["user-workshop"]) && isset($_POST["pwd-workshop"])) {
  $u = $_POST["user-workshop"];
  $p = $_POST["pwd-workshop"];
  if($u=="admin" && $p=="secret") {
	echo "Welcome";
  } else { echo "Incorrect login"; }
  die();
}
?>
<html>
<form method="post" action="login.php">
<p><input type="text" name="user-workshop" value="" placeholder="Username or Email"></p>
        <p><input type="password" name="pwd-workshop" value="" placeholder="Password"></p>
<p class="submit"><input type="submit" name="commit" value="Login"></p>
</form>
</html>

