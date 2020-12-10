<?php

namespace Jumbojett\Session;

class State
{
    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $nonce;

    /**
     * @var null|string
     */
    private $codeVerifier;

    /**
     * State constructor.
     * @param $id
     * @param $nonce
     * @param string|null $codeVerifier
     */
    public function __construct($id, $nonce, $codeVerifier = null) {
        $this->id = $id;
        $this->nonce = $nonce;
        $this->codeVerifier = $codeVerifier;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @return string|null
     */
    public function getCodeVerifier()
    {
        return $this->codeVerifier;
    }

    /**
     * @param $codeVerifier
     * @return State
     */
    public function setCodeVerifier($codeVerifier) {
        return new self($this->id, $this->nonce, $codeVerifier);
    }
}
