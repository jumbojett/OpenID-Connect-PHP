<?php

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use PHPUnit\Framework\MockObject\MockObject;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    /**
     * @return void
     */
    public function testGetRedirectURL()
    {
        $client = new OpenIDConnectClient();

        self::assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        self::assertSame('http://domain.test/path/index.php', $client->getRedirectURL());
    }

    public function testAuthenticateDoesNotThrowExceptionIfClaimsIsMissingNonce()
    {
        $fakeClaims = new \StdClass();
        $fakeClaims->iss = 'fake-issuer';
        $fakeClaims->aud = 'fake-client-id';
        $fakeClaims->nonce = null;

        $_REQUEST['id_token'] = 'abc.123.xyz';
        $_REQUEST['state'] = false;
        $_SESSION['openid_connect_state'] = false;

        /** @var OpenIDConnectClient | MockObject $client */
        $client = $this->getMockBuilder(OpenIDConnectClient::class)->setMethods(['decodeJWT', 'getProviderConfigValue', 'verifyJWTsignature'])->getMock();
        $client->method('decodeJWT')->willReturn($fakeClaims);
        $client->method('getProviderConfigValue')->with('jwks_uri')->willReturn(true);
        $client->method('verifyJWTsignature')->willReturn(true);

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
        $this->assertInstanceOf('Jumbojett\OpenIDConnectClient', unserialize($serialized));
    }
}
