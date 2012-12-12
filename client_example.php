<?php

/**
 *
 * Copyright MITRE 2012
 *
 * OpenIDConnectClient for PHP5
 * Author: Michael Jett <mjett@mitre.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 */

require "OpenIDConnectClient.php5";

$oidc = new OpenIDConnectClient('6e89d765-6333-4759-aa5f-c206052fc1ac',
                                'AI8Nj8zJ8bV4zgC7MzNMxoQo1PXRRemJ9_QL7lPQVDjURSiq4NzgfIa8sfZJ-VS8XnKLCKeYe_N0YWS4MQVZ_28',
                                'http://ground.mitre.org:8080/openid-connect-server/');

// optional
$oidc->setHttpProxy("http://gatekeeper.mitre.org:80");

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

