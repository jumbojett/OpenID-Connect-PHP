<?php

namespace Jumbojett\Session;

/**
 * Only for test purposes
 */
class InMemory implements Session
{
    /**
     * @var State[]
     */
    private $storage = [];

    public function get($id)
    {
        if(isset($this->storage[$id]))
        {
            return $this->storage[$id];
        }
        return null;
    }

    public function commit(State $state)
    {
        $this->storage[$state->getId()] = $state;
    }

    public function cleanup(State $state)
    {
        unset($this->storage[$state->getId()]);
    }
}
