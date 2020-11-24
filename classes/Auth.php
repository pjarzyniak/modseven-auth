<?php
/**
 * User authorization library. Handles user login and logout, as well as secure
 * password hashing.
 *
 * @copyright  (c) 2007-2016  Kohana Team
 * @copyright  (c) 2016-2019  Koseven Team
 * @copyright  (c) since 2019 Modseven Team
 * @license        https://koseven.ga/LICENSE
 */

namespace Modseven\Auth;

use Modseven\Core;
use Modseven\Session;

abstract class Auth
{
    /**
     * Auth instances
     * @var Auth
     */
    protected static Auth $_instance;

    /**
     * Holds the current Session
     * @var Session
     */
    protected Session $_session;

    /**
     * Holds the current configuration
     * @var mixed
     */
    protected $_config;

    /**
     * Singleton pattern
     *
     * @return self
     *
     * @throws Exception
     */
    public static function instance() : self
    {
        if ( ! isset(static::$_instance))
        {
            try
            {
                // Load the configuration for this type
                $config = \Modseven\Config::instance()->load('auth');
            }
            catch (\Modseven\Exception $e)
            {
                throw new Exception($e->getMessage(), null, $e->getCode(), $e);
            }

            $driver = $config->get('driver');

            // Create a new session instance
            static::$_instance = new $driver($config->asArray());
        }

        return static::$_instance;
    }

    /**
     * Loads Session and configuration options.
     *
     * @param array $config Config Options
     *
     * @return  void
     *
     * @throws \Modseven\Exception
     */
    public function __construct($config = [])
    {
        // Save the config in the object
        $this->_config = $config;

        $this->_session = Session::instance($this->_config['session_type']);
    }

    /**
     * Gets the currently logged in user from the session.
     * Returns NULL if no user is currently logged in.
     *
     * @param mixed $default Default value to return if the user is currently not logged in.
     *
     * @return  mixed
     */
    public function getUser($default = null)
    {
        return $this->_session->get($this->_config['session_key'], $default);
    }

    /**
     * Attempt to log in a user by using an ORM object and plain-text password.
     *
     * @param string  $username Username to log in
     * @param string  $password Password to check against
     * @param boolean $remember Enable autologin
     *
     * @return  boolean
     */
    public function login(string $username, string $password, bool $remember = false) : bool
    {
        if (empty($password))
        {
            return false;
        }

        return $this->_login($username, $password, $remember);
    }

    /**
     * Log out a user by removing the related session variables.
     *
     * @param boolean $destroy    Completely destroy the session
     * @param boolean $logout_all Remove all tokens for user
     *
     * @return  boolean
     */
    public function logout(bool $destroy = false, bool $logout_all = false) : bool
    {
        if ($destroy === true)
        {
            // Destroy the session completely
            $this->_session->destroy();
        }
        else
        {
            // Remove the user from the session
            $this->_session->delete($this->_config['session_key']);

            // Regenerate session_id
            $this->_session->regenerate();
        }

        // Double check
        return !$this->loggedIn();
    }

    /**
     * Check if there is an active session. Optionally allows checking for a
     * specific role.
     *
     * @param string $role role name
     *
     * @return  mixed
     */
    public function loggedIn(?string $role = null)
    {
        return ($this->getUser() !== null);
    }

    /**
     * Perform a hmac hash, using the configured method.
     *
     * @param string $str string to hash
     *
     * @return  string
     *
     * @throws Exception
     */
    public function hash(string $str) : string
    {
        if ( ! $this->_config['hash_key'])
        {
            throw new Exception('A valid hash key must be set in your auth config.');
        }

        return hash_hmac($this->_config['hash_method'], $str, $this->_config['hash_key']);
    }

    /**
     * Complete the login
     *
     * @param mixed $user User object
     *
     * @return bool
     */
    protected function completeLogin($user) : bool
    {
        // Regenerate session_id
        $this->_session->regenerate();

        // Store username in session
        $this->_session->set($this->_config['session_key'], $user);

        return true;
    }

    abstract protected function _login(string $username, string $password, bool $remember);

    abstract public function password(string $username);

    abstract public function checkPassword(string $password);

}
