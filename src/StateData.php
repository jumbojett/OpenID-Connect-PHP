<?php

namespace Jumbojett;

class StateData
{
    private $id;
    private $nonce;
    private $codeVerifier;
    private $payload;

    public function __construct(string $id, string $nonce, array $payload, string $codeVerifier = null)
    {
        $this->id = $id;
        $this->nonce = $nonce;
        $this->payload = $payload;
        $this->codeVerifier = $codeVerifier;
    }

    public function getId()
    {
        return $this->id;
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    public function getCodeVerifier()
    {
        return $this->codeVerifier;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function setCodeVerifier(string $codeVerifier): self
    {
        $this->codeVerifier = $codeVerifier;

        return $this;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'payload' => $this->payload,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new StateData(
            $data['id'],
            $data['nonce'],
            $data['payload'] ?? [],
            $data['code_verifier'] ?? null
        );
    }
}
