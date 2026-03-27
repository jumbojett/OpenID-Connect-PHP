<?php

use Jumbojett\OpenIDConnectClient;

require __DIR__ . '/../../../../vendor/autoload.php';

$oidc = new OpenIDConnectClient(
    'http://localhost:8080/realms/testrealm',
    'testclient',
    'testsecret'
);

$oidc->setRedirectURL('http://localhost:8000');

$oidc->authenticate();

$name = $oidc->requestUserInfo('name');
echo "Hi $name";