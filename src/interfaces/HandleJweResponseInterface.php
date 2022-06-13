<?php

namespace Jumbojett\Interfaces;

interface HandleJweResponseInterface
{
    /**
     * Should handle JWE response.
     * @param string $input The JWE to be handled.
     * @return string JWT as json
     */
    public function handleJweResponse($input);
}