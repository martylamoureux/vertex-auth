<?php


namespace Vertex\Auth;


use Vertex\Framework\Application;
use Vertex\Framework\Modeling\Model;
use Vertex\Framework\Modeling\Repository;
use Vertex\Framework\Module;
use Vertex\Framework\Session;

use Hautelook\Phpass\PasswordHash;

class AuthModule extends Module {

    public static $configName = 'auth';

    public function __construct(Application $app) {
        parent::__construct($app);
        $this->internalTwigDirectory = APP_ROOT. DS . 'vendor'. DS . 'vertex'. DS . 'auth'. DS . 'views';
        $this->loadTwig();
    }

    public function getUserModelName() {
        return $this->getConfig('model', 'User');
    }

    public function createModel() {
        return Model::create($this->getUserModelName());
    }

    public function getLoggedUser() {
        if (!Session::has('__auth'))
            return NULL;

        $token = Session::get('__auth');

        $repo = new Repository($this->getUserModelName());
        $entity = $repo->query()->where($this->getConfig('token_field', 'auth_token'), $token)->first();
        return $entity;
    }

    public function isLogged() {
        if (!Session::has('__auth'))
            return false;

        return $this->getLoggedUser() !== NULL;
    }

    public function check($username, $password) {
        return $this->getUser($username, $password) !== NULL;
    }

    public function getUser($username, $password) {
        $usernameField = $this->getConfig('username_field', 'username');
        $passwordField = $this->getConfig('password_field', 'password');

        $repo = new Repository($this->getUserModelName());
        $entity = $repo->query()
            ->where($usernameField, $username)
            ->first();

        $hasher = new PasswordHash(8, false);
        $test = $hasher->CheckPassword($password, $entity->get($passwordField));

        if (!$test)
            return NULL;

        return $entity;
    }

    public function login($username, $password, $remember = false) {
        $user = $this->getUser($username, $password);
        if ($user !== NULL) {
            $tokenField = $this->getConfig('token_field', 'auth_token');
            $token = $user->get($tokenField);
            if ($token === NULL || $token == '') {
                $token = $this->generateToken();
                $user->$tokenField = $token;
                $user->save();
            }
            //exit(var_dump($token));
            if ($remember)
                Session::store('__auth', $token);
            else
                Session::temp('__auth', $token);

            return true;
        } else
            return false;
    }

    private function generateToken() {
        $alphabet = "abcdefghijklmnopqrstuwxyz0123456789";
        $pass = [];
        $alphaLength = strlen($alphabet) - 1;
        for ($i = 0; $i < 16; $i++) {
            $n = rand(0, $alphaLength);
            $pass[] = $alphabet[$n];
        }
        return implode($pass);
    }

    public function logout() {
        Session::delete('__auth');
    }

    public function encryptPassword(Model $user) {
        $passwordField = $this->getConfig('password_field', 'password');

        if (!array_key_exists($passwordField, $user->attributes))
            return false;

        $password = $user->$passwordField;
        $hasher = new PasswordHash(8, false);
        $password = $hasher->HashPassword($password);

        $user->$passwordField = $password;
        return true;
    }

    public function needsLogin() {
        $user = $this->getLoggedUser();
        if ($user === NULL) {
            $loginRoute = $this->getConfig('login_route', NULL);
            if ($loginRoute === NULL)
                static::$app->raise(403, "Forbidden");
            $controller = $loginRoute[0];
            $action = $loginRoute[1];
            array_shift($loginRoute);
            array_shift($loginRoute);

            static::$app->stopAndRedirect($controller, $action, $loginRoute);
        }
        return $user;
    }
} 