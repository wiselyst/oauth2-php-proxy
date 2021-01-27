<?php

namespace Wiselyst\OAuth2Proxy;

use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class Authentication{
    
    /**
     * @var Session
     */
    private $session;

    /**
     * Http client
     * @var HttpClientInterface
     */
    protected $httpClient;

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

    public function __construct(HttpClientInterface $httpClient, SessionInterface $session){
        $this->session = $session;
        $this->httpClient = $httpClient;
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

    /**
     * Attempt an access token refresh
     * @return true
     */
    public function renewAccessToken($host, $clientId, $clientSecret){
        if(!$this->getAccessToken()){
            return false;
        }

        $this->session->clear();
        $this->session->migrate(false);

        $response = $this->httpClient->request('POST', $host . OAuth2Proxy::REMOTE_TOKEN_ENDPOINT, [
            'body' => [
                'grant_type' => 'refresh_token',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $this->getRefreshToken(),
            ]
        ]);
        
        $parsedResponse = json_decode($response, true);
        
        if(isset($parsedResponse['refresh_token'])){
            $this->authentication->setAccessToken($parsedResponse['refresh_token']);
        }

        if(isset($parsedResponse['access_token'])){
            $this->authentication->setAccessToken($parsedResponse['access_token']);
            return true;
        }

        return false;
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