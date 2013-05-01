PHP OpenID Connect Basic Client
========================
A simple library that allows an application to authenticate a user through the basic OpenID Connect flow.
This library hopes to encourage OpenID Connect use by making it simple enough for a developer with little knowledge of
the OpenID Connect protocol to setup authentication.

# Requirements #
 1. PHP 5.2 or greater 
 2. CURL extension
 3. JSON extension

## Example 1: Basic Client ##

```php
$oidc = new OpenIDConnectClient('https://id.provider.com/',
                                'ClientIDHere',
                                'ClientSecretHere');

$oidc->authenticate();
$name = $oidc->requestUserInfo('given_name');
                                 
```

[See openid spec for available user attributes][1]

## Example 2: Dynamic Registration ##

```php
$oidc = new OpenIDConnectClient("https://id.provider.com/");

$oidc->register();
$client_id = $oidc->getClientID();
$client_secret = $oidc->getClientSecret();

// Be sure to add logic to store the client id and client secret
```


  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
### Todo ###
- Dynamic registration does not support registration auth tokens and endpoints
