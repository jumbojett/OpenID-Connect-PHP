<?php

namespace Jumbojett;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class EventsChecker implements ClaimChecker
{
    public function __construct(protected string $event)
    {

    }

    public function checkClaim($value): void
    {

        $events = (array) $value;
        if (!isset($events['http://schemas.openid.net/event/backchannel-logout']) ||
            !is_object($events['http://schemas.openid.net/event/backchannel-logout'])) {
            throw new InvalidClaimException('The claim "events" does not contain the expected value.', 'events', $events);
        }

    }

    public function supportedClaim(): string
    {
        return 'events';
    }
}
