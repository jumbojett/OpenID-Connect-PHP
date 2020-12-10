<?php
namespace Jumbojett\Session;

interface Session
{
    /**
     * @param string $id
     * @return State
     */
    public function get($id);

    /**
     * @param State $state
     * @return void
     */
    public function commit(State $state);

    /**
     * @param State $state
     * @return void
     */
    public function cleanup(State $state);
}
