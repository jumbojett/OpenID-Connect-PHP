<?php

namespace Jumbojett;

class Response
{
    public function __construct(
        private readonly int $status,
        private readonly string $contentType,
        private readonly string $body,
    ) {
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function getContentType(): string
    {
        return $this->contentType;
    }

    public function getBody(): string
    {
        return $this->body;
    }
}
