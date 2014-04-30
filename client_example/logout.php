<?php
	session_start();

	$id_token = $_SESSION['openid_id_token'];
	$logout_url = $_SESSION['openid_logout_url'];

	session_destroy();

#	header("Location: $logout_url?id_token_hint=$id_token");
?>
<script>
function logout() {
document.getElementById('logout_form').submit();
}
</script>
<body onload='logout();'>
<form id='logout_form' action='<?php echo $logout_url; ?>' method='POST'>
<input type='text' name='id_token' value='<?php echo $id_token; ?>'/>
</form>
</body>
