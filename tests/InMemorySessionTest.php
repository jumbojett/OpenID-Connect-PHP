<?php

use Jumbojett\Session\InMemory;
use Jumbojett\Session\State;

class InMemorySessionTest extends PHPUnit_Framework_TestCase
{
    public function testCommit()
    {
        $session = new InMemory();
        $state = new State('stateId', 'stateNonce', 'stateCodeVerifier');
        $session->commit($state);

        $this->assertEquals($state->getId(), $session->get('stateId')->getId());
        $this->assertEquals($state->getNonce(), $session->get('stateId')->getNonce());
    }

    public function testCleanup()
    {
        $session = new InMemory();
        $state = new State('stateId', 'stateNonce', 'stateCodeVerifier');
        $session->commit($state);
        $session->cleanup($state);

        $this->assertEquals(null, $session->get('stateId'));
    }

    public function testNotExisting()
    {
        $session = new InMemory();
        $this->assertEquals(null, $session->get('notExistingId'));
    }
}
