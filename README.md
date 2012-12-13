OpenID Connect for PHP 5
========================
A simple client library
------------------------

# Goals #
 1. Simple
 2. Clean
 3. Compact
 4. Free from spec jargon
 5. List item

----------

## Create an instance ##

    $oidc = new OpenIDConnectClient('clientID',
                                    'clientSecret',
                                    'https://provider.url');

## Add optional parameters ##
### Configure a proxy ###

    $oidc->setHttpProxy("http://my.proxy.org:80");

### Add a scope###

    $oidc->addScope('openid');


## Authenticate ##

    try {
        $oidc->authenticate();
    }
