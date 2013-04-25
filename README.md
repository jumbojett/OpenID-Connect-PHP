OpenID Connect for PHP 5
========================
A simple "basic client" library that allows an application to authenticate a user via an OpenID Connect server.

# Goals #
 1. Simple
 2. Clean
 3. Compact
 4. Free from spec jargon

----------

## Create an instance ##

```php
$oidc = new OpenIDConnectClient('clientID',
                                'clientSecret',
                                'https://provider.url');
                                 
```

## Add optional parameters ##
### Configure a proxy ###

```php
$oidc->setHttpProxy("http://my.proxy.org:80");
```

### Add a scope###

```php
$oidc->addScope('openid');
```

## Authenticate ##

```php
try {
    $oidc->authenticate();
}
```

## Learn about the user ##

```php
$name = $oidc->requestUserInfo('given_name');
```

[See openid spec for available user attributes][1]


  [1]: http://openid.net/specs/openid-connect-basic-1_0-15.html#id_res
  
## Todo ##
- Support dynamic registration
