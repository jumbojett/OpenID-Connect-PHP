OpenID Connect for PHP 5
========================
A simple "basic client" library that allows an application to authenticate a user through an OpenID Connect provider.
This library hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of
the OpenID Connect protocol to setup authentication.

# Goals #
 1. Simple
 2. Clean
 3. Compact
 4. Free from spec jargon

----------

## Example 1: Basic Client ##

```php
$oidc = new OpenIDConnectClient('http://id.provider.com/',
                                'ClientIDHere',
                                'ClientSecretHere');

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
                                 
```

## Example 2: Dynamic Registration ##

```php
$oidc = new OpenIDConnectClient("http://id.provider.com/");

$oidc->register();
$client_id = $oidc->getClientID();
$client_secret = $oidc->getClientSecret();

// Be sure to add logic to store the client id and client secret
```


[See openid spec for available user attributes][1]


  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
### Todo ###
- Dynamic registration does not support registration auth tokens and endpoints
