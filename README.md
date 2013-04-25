OpenID Connect for PHP 5
========================
A simple "basic client" library
------------------------

# Goals #
 1. Simple
 2. Clean
 3. Compact
 4. Free from spec jargon

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

## Learn about the user ##

    $name = $oidc->requestUserInfo('given_name');

[See openid spec for available user attributes][1]


  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
