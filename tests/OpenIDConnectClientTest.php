<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use PHPUnit\Framework\MockObject\MockObject;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    public function testValidateClaims()
    {
        $client = new class extends OpenIDConnectClient {
            public function testVerifyJWTClaims($claims): bool
            {
                return $this->verifyJWTClaims($claims);
            }
            public function getIdTokenPayload()
            {
                return (object)[
                    'sub' => 'sub'
                ];
            }
        };
        $client->setClientID('client-id');
        $client->setIssuer('issuer');
        $client->setIdToken('');

        # simple aud
        $valid = $client->testVerifyJWTClaims((object)[
            'aud' => 'client-id',
            'iss' => 'issuer',
            'sub' => 'sub',
        ]);
        self::assertTrue($valid);

        # array aud
        $valid = $client->testVerifyJWTClaims((object)[
            'aud' => ['client-id'],
            'iss' => 'issuer',
            'sub' => 'sub',
        ]);
        self::assertTrue($valid);

        # aud not matching
        $valid = $client->testVerifyJWTClaims((object)[
            'aud' => ['ipsum'],
            'iss' => 'issuer',
            'sub' => 'sub',
        ]);
        self::assertFalse($valid);

        # sub not matching
        $valid = $client->testVerifyJWTClaims((object)[
            'aud' => ['client-id'],
            'iss' => 'issuer',
            'sub' => 'sub-invalid',
        ]);
        self::assertFalse($valid);

        # sub missing
        $valid = $client->testVerifyJWTClaims((object)[
            'aud' => ['client-id'],
            'iss' => 'issuer',
        ]);
        self::assertFalse($valid);
    }
    public function testJWTDecode()
    {
        $client = new OpenIDConnectClient();
        # access token
        $client->setAccessToken('');
        $header = $client->getAccessTokenHeader();
        self::assertEquals('', $header);
        $payload = $client->getAccessTokenPayload();
        self::assertEquals('', $payload);

        # id token
        $client->setIdToken('');
        $header = $client->getIdTokenHeader();
        self::assertEquals('', $header);
        $payload = $client->getIdTokenPayload();
        self::assertEquals('', $payload);
    }

    public function testGetNull()
    {
        $client = new OpenIDConnectClient();
        self::assertNull($client->getAccessToken());
        self::assertNull($client->getRefreshToken());
        self::assertNull($client->getIdToken());
        self::assertNull($client->getClientName());
        self::assertNull($client->getClientID());
        self::assertNull($client->getClientSecret());
        self::assertNull($client->getCertPath());
    }

    public function testResponseTypes()
    {
        $client = new OpenIDConnectClient();
        self::assertEquals([], $client->getResponseTypes());

        $client->setResponseTypes('foo');
        self::assertEquals(['foo'], $client->getResponseTypes());

        $client->setResponseTypes(['bar', 'ipsum']);
        self::assertEquals(['foo', 'bar', 'ipsum'], $client->getResponseTypes());
    }

    public function testGetRedirectURL()
    {
        $client = new OpenIDConnectClient();

        self::assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        $_SERVER['SERVER_PORT'] = '443';
        self::assertSame('http://domain.test/path/index.php', $client->getRedirectURL());

        $_SERVER['SERVER_PORT'] = '8888';
        self::assertSame('http://domain.test:8888/path/index.php', $client->getRedirectURL());
    }

    public function testAuthenticateDoesNotThrowExceptionIfClaimsIsMissingNonce()
    {
        $fakeClaims = new StdClass();
        $fakeClaims->iss = 'fake-issuer';
        $fakeClaims->aud = 'fake-client-id';
        $fakeClaims->sub = 'fake-sub';
        $fakeClaims->nonce = null;

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['state'] = false;
        $_SESSION['openid_connect_state'] = false;

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['decodeJWT', 'getProviderConfigValue', 'verifyJWTSignature'])->getMock();
        $client->method('decodeJWT')->willReturn($fakeClaims);
        $client->method('getProviderConfigValue')->with('jwks_uri')->willReturn(true);
        $client->method('verifyJWTSignature')->willReturn(true);

        $client->setClientID('fake-client-id');
        $client->setIssuer('fake-issuer');
        $client->setIssuerValidator(function() {
            return true;
        });
        $client->setAllowImplicitFlow(true);
        $client->setProviderURL('https://jwt.io/');

        try {
            $authenticated = $client->authenticate();
            $this->assertTrue($authenticated);
        } catch ( OpenIDConnectClientException $e ) {
            if ( $e->getMessage() === 'Unable to verify JWT claims' ) {
                self::fail( 'OpenIDConnectClientException was thrown when it should not have been.' );
            }
        }
    }

    public function testSerialize()
    {
        $client = new OpenIDConnectClient('https://example.com', 'foo', 'bar', 'baz');
        $serialized = serialize($client);
        $this->assertInstanceOf(OpenIDConnectClient::class, unserialize($serialized));
    }

    /**
     * @dataProvider provider
     */
    public function testAuthMethodSupport($expected, $authMethod, $clientAuthMethods, $idpAuthMethods)
    {
        $client = new OpenIDConnectClient();
        if ($clientAuthMethods !== null) {
            $client->setTokenEndpointAuthMethodsSupported($clientAuthMethods);
        }
        $this->assertEquals($expected, $client->supportsAuthMethod($authMethod, $idpAuthMethods));
    }

    public function provider(): array
    {
        return [
            'client_secret_basic - default config' => [true, 'client_secret_basic', null, ['client_secret_basic']],

            'client_secret_jwt - default config' => [false, 'client_secret_jwt', null, ['client_secret_basic', 'client_secret_jwt']],
            'client_secret_jwt - explicitly enabled' => [true, 'client_secret_jwt', ['client_secret_jwt'], ['client_secret_basic', 'client_secret_jwt']],

            'private_key_jwt - default config' => [false, 'private_key_jwt', null, ['client_secret_basic', 'client_secret_jwt', 'private_key_jwt']],
            'private_key_jwt - explicitly enabled' => [true, 'private_key_jwt', ['private_key_jwt'], ['client_secret_basic', 'client_secret_jwt', 'private_key_jwt']],

        ];
    }

    /**
     * @covers       Jumbojett\\OpenIDConnectClient::verifyLogoutTokenClaims
     * @dataProvider provideTestVerifyLogoutTokenClaimsData
     * @throws OpenIDConnectClientException
     */
    public function testVerifyLogoutTokenClaims( $claims, $expectedResult )
    {
        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['decodeJWT'])->getMock();

        $client->setClientID('fake-client-id');
        $client->setIssuer('fake-issuer');
        $client->setIssuerValidator(function() {
            return true;
        });
        $client->setProviderURL('https://jwt.io/');

        $actualResult = $client->verifyLogoutTokenClaims( $claims );

        $this->assertEquals( $expectedResult, $actualResult );
    }

    /**
     * @return array
     */
    public function provideTestVerifyLogoutTokenClaimsData(): array
    {
        return [
            'valid-single-aud' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'valid-multiple-auds' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'invalid-no-sid-and-no-sub' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'valid-no-sid' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'valid-no-sub' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'invalid-with-nonce' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                    'nonce' => 'must-not-be-set'
                ],
                false
            ],
            'invalid-no-events' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'must-not-be-set'
                ],
                false
            ],
            'invalid-no-backchannel-event' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [],
                    'nonce' => 'must-not-be-set'
                ],
                false
            ],
            'invalid-no-iat' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ]
                ],
                false
            ],
            'invalid-bad-iat' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'iat' => time() + 301,
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ]
                ],
                false
            ],
            'invalid-no-exp' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ]
                ],
                false
            ],
            'invalid-bad-exp' => [
                (object)[
                    'iss' => 'fake-issuer',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() - 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ]
                ],
                false
            ],
        ];
    }

    public function testLeeway()
    {
        // Default leeway is 300
        $client = new OpenIDConnectClient();
        $this->assertEquals(300, $client->getLeeway());

        // Set leeway to 100
        $client->setLeeway(100);
        $this->assertEquals(100, $client->getLeeway());
    }
}
