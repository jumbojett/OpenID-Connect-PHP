# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Added
* 

### Changed
* 

### Removed
*

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
