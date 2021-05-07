<?php

use Jumbojett\OpenIDConnectExceptionFactory;

class ExceptionFactoryTest extends PHPUnit_Framework_TestCase
{
    public function testExceptionJWT()
    {
        // This version of PHPUnit doesn't support expectExceptionCode, for this reason
        // I created another method used by `throwException()`.
        // Creates a new exception message.
        $this->assertEquals(
            'Unable to verify JWT claims',
            OpenIDConnectExceptionFactory::generateMessage(
                OpenIDConnectExceptionFactory::UNABLE_VERIFY_JWT_CLAIMS
            )
        );

        // Creates a new exception message with params.
        $this->assertEquals(
            'Error missing part 100 in token',
            OpenIDConnectExceptionFactory::generateMessage(
                OpenIDConnectExceptionFactory::TOKEN_PART_MISSING,
                [100]
            )
        );
    }
}
