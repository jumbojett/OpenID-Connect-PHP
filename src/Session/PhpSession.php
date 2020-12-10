<?php
namespace Jumbojett\Session;


use function session_write_close;

class PhpSession implements Session
{
    /**
     * @var array
     */
    private $options;

    public function __construct($options = [])
    {
        $this->options = $options;
    }

    private function start() {
        if (!isset($_SESSION)) {
            session_start($this->options);
        }
    }

    public function get($id) {
        $this->start();

        if(isset($_SESSION[$id]))  {
            return new State($id, $_SESSION[$id]['nonce'], $_SESSION[$id]['code_verifier']);
        }

        return null;
    }

    public function commit(State $state) {
        $this->start();

        $_SESSION[$state->getId()] = [
            'nonce' => $state->getNonce(),
            'code_verifier' => $state->getCodeVerifier()
        ];

        session_write_close();
    }

    public function cleanup(State $state) {
        $this->start();

        unset($_SESSION[$state->getId()]);

        session_write_close();
    }
}
