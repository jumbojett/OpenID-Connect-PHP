# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [0.9.2]

### Added
* Support for [PKCE](https://tools.ietf.org/html/rfc7636). Currently the supported methods are 'plain' and 'S256'.

## [0.9.1]

### Added
* Add support for MS Azure Active Directory B2C user flows 

### Changed
* Fix at_hash verification #200
* Getters for public parameters #204
* Removed client ID query parameter when making a token request using Basic Auth
* Use of `random_bytes()` for token generation instead of `uniqid()`; polyfill for PHP < 7.0 provided.

### Removed
* Removed explicit content-length header - caused issues with proxy servers


## [0.9.0]

### Added
* php 7.4 deprecates array_key_exists on objects, use property_exists in getVerifiedClaims and requestUserInfo
* Adding a header to indicate JSON as the return type for userinfo endpoint #151
* ~Updated OpenIDConnectClient to conditionally verify nonce #146~
* Add possibility to change enc_type parameter for http_build_query #155
* Adding OAuth 2.0 Token Introspection #156
* Add optional parameters clientId/clientSecret for introspection #157 & #158
* Adding OAuth 2.0 Token Revocation #160
* Adding issuer validator #145
* Adding signing algorithm PS256 #180
* Check http status of request user info #186
* URL encode clientId and clientSecret when using basic authentication, according to https://tools.ietf.org/html/rfc6749#section-2.3.1 #192
* Adjust PHPDoc to state that null is also allowed #193

### Changed
* Bugfix/code cleanup #152
  * Cleanup PHPDoc #46e5b59
  * Replace unnecessary double quotes with single quotes #2a76b57
  * Use original function names instead of aliases #1f37892
  * Remove unnecessary default values #5ab801e
  * Explicit declare field $redirectURL #9187c0b
  * Remove unused code #1e65384
  * Fix indent #e9cdf56
  * Cleanup conditional code flow for better readability #107f3fb
 * Added strict type comparisons #167
* Bugfix: required `openid` scope was omitted when additional scopes were registered using `addScope` method. This resulted in failing OpenID process.

## [0.8.0]

### Added
* Fix `verifyJWTsignature()`: verify JWT to prevent php errors and warnings on invalid token

### Changed
* Decouple session manipulation, it's allow use of other session libraries #134
* Broaden version requirements of the phpseclib/phpseclib package. #144

## [0.7.0]

### Added
* Add "license" field to composer.json #138
* Ensure key_alg is set when getting key #139
* Add option to send additional registration parameters like post_logout_redirect_uris. #140

### Changed
* disabled autoload for Crypt_RSA + makre refreshToken() method tolerant for errors #137

### Removed
*

## [0.6.0]

### Added
* Added five minutes leeway due to clock skew between openidconnect server and client.
* Fix save access_token from request in implicit flow authentication #129
* verifyJWTsignature() method private -> public #126
* Support for providers where provider/login URL is not the same as the issuer URL. #125
* Support for providers that has a different login URL from the issuer URL, for instance Azure Active Directory. Here, the provider URL is on the format: https://login.windows.net/(tenant-id), while the issuer claim actually is on the format: https://sts.windows.net/(tenant-id).

### Changed
* refreshToken method update #124

### Removed
*

## [0.5.0]
## Added
* Implement Azure AD B2C Implicit Workflow

## [0.4.1]
## Changed
* Documentation updates for include path.

## [0.4]
### Added
* Timeout is configurable via setTimeout method. This addresses issue #94.
* Add the ability to authenticate using the Resource Owner flow (with or without the Client ID and ClientSecret). This addresses issue #98
* Add support for HS256, HS512 and HS384 signatures
* Removed unused calls to $this->getProviderConfigValue("token_endpoint_…

### Changed

### Removed
