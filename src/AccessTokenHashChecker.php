<?php

namespace Jumbojett;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class AccessTokenHashChecker implements ClaimChecker
{
    public function __construct(private OpenIDConnectClient $openIDConnectClient)
    {

    }

    public function checkClaim($value): void
    {
        $alg = $this->openIDConnectClient->getIdTokenHeader()->alg;

        $bit = match ($alg) {
            'EdDSA' => '512',
            default => substr($alg, 2, 3),
        };

        $len = ((int)$bit) / 16;
        $expected_at_hash = $this->openIDConnectClient->urlEncode(substr(hash('sha'.$bit, $this->openIDConnectClient->getAccessToken(), true), 0, $len));

        if ($value !== $expected_at_hash) {
            throw new InvalidClaimException('The claim "at_hash" does not match the Access Token hash value.', 'at_hash', $value);
        }
    }

    public function supportedClaim(): string
    {
        return 'at_hash';
    }
}
