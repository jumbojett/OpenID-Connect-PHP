<?php

/**
 *
 * Copyright MITRE 2012
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Creative Commons License, Version 3.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://creativecommons.org/licenses/by/3.0/us/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

require "OpenIDConnectClient.php5";

$oidc = new OpenIDConnectClient('clientIDHere',
                                'clientSecretHere',
                                'http://providerURLHere');

// optional
// $oidc->setHttpProxy("http://");

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');

?>

<html>
<head>
    <title>Example OpenID Connect Client Use</title>
    <style>
        body {
            font-family: 'Lucida Grande', Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>
<?php if ($name): ?>
    <div>
        Hello <?= $name ?>
    </div>
<?php endif ?>

</body>
</html>

