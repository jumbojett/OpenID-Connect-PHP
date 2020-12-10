<?php

namespace Jumbojett\Session;

class Redis implements Session
{
    const PREFIX = 'oidc_state___';
    const SEPARATOR = '___';
    const TTL = 30;

    /**
     * @var \Redis
     */
    private $redis;

    public function __construct(\Redis $redis){
        $this->redis = $redis;
    }


    public function get($id)
    {
        $key = $this->buildKey($id);
        $serialized = $this->redis->get($key);
        if($serialized) {
            return $this->deserialize($id, $serialized);
        }
        return null;
    }

    public function commit(State $state)
    {
        $key = $this->buildKey($state->getId());
        $this->redis->set($key, $this->serialize($state), self::TTL);
    }

    public function cleanup(State $state)
    {
        $key = $this->buildKey($state->getId());
        $this->redis->del($key);
    }

    private function serialize(State $state) {
        return $state->getNonce() . self::SEPARATOR . $state->getCodeVerifier();
    }

    private function deserialize($id, $serialized) {
        $parts = explode(self::SEPARATOR, $serialized, 2);
        return new State($id, $parts[0], isset($parts[1]) ? $parts[1] : null);
    }

    private function buildKey($id) {
        return self::PREFIX . $id;
    }
}
