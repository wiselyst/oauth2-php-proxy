<?php

namespace Wiselyst\OAuth2Proxy;

use Symfony\Component\HttpFoundation\Session\Session;

class Authentication{
    
    /**
     * @var Session
     */
    private $session;

    /**
     * Session name for the access token
     * @var string
     */
    const ACCESS_TOKEN_SESSION = 'oauth_access_token';

    /**
     * Session name for the refresh token
     * @var string
     */
    const REFRESH_TOKEN_SESSION = 'oauth_refresh_token';

    public function __construct(){
        $this->session = new Session();

        if(!$this->session->isStarted()){
            $this->session->start();
        }
    }

    public function setAccessToken(string $accessToken){
        return $this->session->set(self::ACCESS_TOKEN_SESSION, $accessToken);
    }

    public function getAccessToken(){
        return $this->session->get(self::ACCESS_TOKEN_SESSION);
    }
    
    public function setRefreshToken(string $refreshToken){
        return $this->session->set(self::REFRESH_TOKEN_SESSION, $refreshToken);
    }

    public function getRefreshToken(){
        return $this->session->get(self::REFRESH_TOKEN_SESSION);
    }

    public function isAuthorized(){
        if($this->getAccessToken()){ //TODO: check if user is authenticated
            return true;
        }

        return false;
    }

    /**
     * Attempt an access token refresh
     * @return true
     */
    public function renewAccessToken(){
        $this->session->clear();
        $this->session->migrate(false);
        return true;
    }

    /**
     * Clears the current section
     * @return void
     */
    public function logout(){
        $this->session->clear();
        $this->session->migrate(true);
    }
}