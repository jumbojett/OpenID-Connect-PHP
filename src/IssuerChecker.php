<?php

namespace Jumbojett;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class IssuerChecker implements ClaimChecker
{
    public function __construct(private OpenIDConnectClient $openIDConnectClient)
    {

    }

    public function checkClaim($value): void
    {
        $issuerValidator = $this->openIDConnectClient->getIssuerValidator();

        if ($issuerValidator !== null) {
            $isValid = $issuerValidator->__invoke($value);
        } else {
            $isValid = ($value === $this->openIDConnectClient->getIssuer() || $value === $this->openIDConnectClient->getWellKnownIssuer() || $value === $this->openIDConnectClient->getWellKnownIssuer(true));
        }

        if (!$isValid) {
            throw new InvalidClaimException('The claim "iss" does not match the expected value.', 'iss', $value);
        }
    }

    public function supportedClaim(): string
    {
        return 'iss';
    }
}
