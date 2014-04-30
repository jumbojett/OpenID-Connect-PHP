<?php
	session_start();

	if(isset($_SESSION['login_error'])) {
		$error = $_SESSION['login_error'];
		unset($_SESSION['login_error']);
?>
<div class='error'>
<?php echo $error;  ?>
</div>
<?php
	}

	if(!isset($_SESSION['user'])) {
?>
<a href='auth.php'>Click here to login</a>
<?php
	}
	else {
		$user = $_SESSION['user'];
		echo "Welcome $user<br/>";
		echo "$_SESSION[openid_id_token]<br/>";
		echo "$_SESSION[openid_logout_url]<br/>";
		echo "<a href='logout.php'>Logout</a>";
	}
?>
