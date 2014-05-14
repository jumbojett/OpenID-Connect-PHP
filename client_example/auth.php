<?php
	session_start();

	require_once "OpenIDConnectClient.php5";

	try {
		$oidc = new OpenIDConnectClient('url',
                                  'test',
                                  'test');
		$oidc->addScope('openid');
		$oidc->addScope('profile');
		$oidc->authenticate();
		$name = $oidc->requestUserInfo('given_name');
		$logout = $oidc->getLogOutURL();

		$_SESSION['user'] = $name;
		$_SESSION['openid_id_token'] = $oidc->getIdToken();
		$_SESSION['openid_logout_url'] = $logout;
	}
	catch(Exception $e) {
		$_SESSION['login_error'] = "OpenAM failed to authorise you. $e->getMessage()";
	}

	header('Location: ./');
?>
