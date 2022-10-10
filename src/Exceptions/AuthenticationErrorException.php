<?php

declare(strict_types=1);

namespace Jumbojett\OpenIDConnectClient\Exceptions;

use Exception;

/**
 * Authentication Error Exception Class
 * https://openid.net/specs/openid-connect-core-1_0.html#AuthError
 */
class AuthenticationErrorException extends Exception
{
    /**
     * @var string
     */
    private $error;

    /**
     * @var string
     */
    private $error_description;

    /**
     * @var string
     */
    private $error_uri;

    public function __construct(string $error = null, string $error_description = null, string $error_uri = null)
    {
        $this->error = $error;
        $this->error_description = $error_description;
        $this->error_uri = $error_uri;

        $desc = isset($this->error_description) ? ' Description: ' . $this->error_description : '';
        parent::__construct('Error: ' . $this->error .$desc);
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getErrorDescription(): string
    {
        return $this->error_description;
    }

    public function getErrorUri(): string
    {
        return $this->error_uri;
    }
}