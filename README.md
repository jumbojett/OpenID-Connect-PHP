OpenID Connect for PHP 5
========================
A simple "basic client" library that allows an application to authenticate a user via an OpenID Connect server.

# Goals #
 1. Simple
 2. Clean
 3. Compact
 4. Free from spec jargon

----------

## It's easy! ##

```php
$oidc = new OpenIDConnectClient('http://myproviderURL.com/',
                                'ClientIDHere',
                                'ClientSecretHere');

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
                                 
```

## Dynamic Registration Example ##

```php
$client_id = $_SESSION['client_id'];
$client_secret = $_SESSION['client_secret'];
$provider = "http://id.provider.com/";

// If we don't have a client id or secret then obtain one
if (!$client_id || !$client_secret) {
    $oidc = new OpenIDConnectClient($provider);
    $_SESSION['client_id'] = $oidc->getClientID();
    $_SESSION['client_secret'] = $oidc->getClientSecret();
} else {
    $oidc = new OpenIDConnectClient($provider, $client_id, $client_secret);
}

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
```


[See openid spec for available user attributes][1]


  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
### Todo ###
- Dynamic registration does not support registration auth tokens and endpoints
