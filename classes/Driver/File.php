<?php
/**
 * File Auth driver.
 * [!!] this Auth driver does not support roles nor autologin.
 *
 * @copyright  (c) 2007-2016  Kohana Team
 * @copyright  (c) since 2016 Koseven Team
 * @license        https://koseven.ga/LICENSE
 */

namespace Modseven\Auth\Driver;

use KO7\Arr;

use Modseven\Auth\Auth;
use Modseven\Auth\Exception;

class File extends Auth
{
    /**
     * User list
     * @var array
     */
    protected array $_users;

    /**
     * Constructor loads the user list into the class.
     *
     * @param array $config Configuration
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        // Load user list
        $this->_users = Arr::get($config, 'users', []);
    }

    /**
     * Logs a user in.
     *
     * @param string  $username Username
     * @param string  $password Password
     * @param boolean $remember Enable autologin (not supported)
     *
     * @return  boolean
     *
     * @throws Exception
     */
    protected function _login(string $username, string $password, bool $remember) : bool
    {
        if ($remember)
        {
            throw new Exception('File based auth does not support remember');
        }

        // Create a hashed password
        $password = $this->hash($password);

        if (isset($this->_users[$username]) && $this->_users[$username] === $password)
        {
            // Complete the login
            return $this->complete_login($username);
        }

        // Login failed
        return false;
    }

    /**
     * Forces a user to be logged in, without specifying a password.
     *
     * @param mixed $username Username
     *
     * @return  boolean
     */
    public function force_login($username) : bool
    {
        // Complete the login
        return $this->complete_login($username);
    }

    /**
     * Get the stored password for a username.
     *
     * @param mixed $username Username
     *
     * @return  string
     */
    public function password($username) : string
    {
        return Arr::get($this->_users, $username, false);
    }

    /**
     * Compare password with original (plain text). Works for current (logged in) user
     *
     * @param string $password Password
     *
     * @return  bool
     */
    public function check_password(string $password) : bool
    {
        $username = $this->get_user();

        if ($username === false)
        {
            return false;
        }

        return ($password === $this->password($username));
    }

}
