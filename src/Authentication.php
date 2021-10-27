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
     * CSRF Protection service
     *
     * @var CsrfProtection
     */
    protected $csrf;

    public function __construct(HttpClientInterface $httpClient, SessionInterface $session, CsrfProtection $csrf){
        $this->session = $session;
        $this->httpClient = $httpClient;
        $this->csrf = $csrf;
    }

    /**
     * Session name to store the access token
     * @var string
     */
    const ACCESS_TOKEN_SESSION = 'oauth_access_token';

    /**
     * Session name to store the refresh token
     * @var string
     */
    const REFRESH_TOKEN_SESSION = 'oauth_refresh_token';

    /**
     * Session name to store the grant type
     * @var string
     */
    const GRANT_TYPE_SESSION = 'oauth_grant_type';


    /**
     * Set access token string
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken){
        return $this->session->set(self::ACCESS_TOKEN_SESSION, $accessToken);
    }

    /**
     * Get access token string
     * @return string
     */
    public function getAccessToken(){
        return $this->session->get(self::ACCESS_TOKEN_SESSION);
    }
    
    /**
     * Set refresh token string
     * @param string $refreshToken
     */
    public function setRefreshToken(string $refreshToken){
        return $this->session->set(self::REFRESH_TOKEN_SESSION, $refreshToken);
    }

    /**
     * Get refresh token string
     * @return string
     */
    public function getRefreshToken(){
        return $this->session->get(self::REFRESH_TOKEN_SESSION);
    }

    /**
     * Set the grant type used for the authentication
     * @param string $grantType
     */
    protected function setGrantType(string $grantType){
        return $this->session->set(self::GRANT_TYPE_SESSION, $grantType);
    }

    /**
     * Get the grant type used for the authentication
     * @return string
     */
    public function getGrantType(){
        return $this->session->get(self::GRANT_TYPE_SESSION);
    }

    /**
     * Request and store a new access token
     * 
     * @param string $host Remote host
     * @param string $grantType client_credentials or password grant type
     * @param string $clientId Client id
     * @param string $clientSecret Client secret
     * @param string $username Username
     * @param string $password Password
     * 
     * @return ResponseInterface
     */
    public function requestAccessToken(string $host, string $grantType, string $clientId, string $clientSecret, string $username = '', string $password = '', string $scope = ''){
        
        $this->logout();

        $body = [];
        $body['grant_type'] = $grantType;
        $body['client_id'] = $clientId;
        $body['client_secret'] = $clientSecret;
        $body['scope'] = $scope;

        if($grantType === 'password'){
            $body['username'] = $username;
            $body['password'] = $password;
        }
        
        $response = $this->httpClient->request('POST', $host . OAuth2Proxy::$REMOTE_TOKEN_ENDPOINT, [
            'body' => $body
        ]);

        $parsedResponse = json_decode($response->getContent(false), true);
        
        if($response->getStatusCode() === 200){
            if(isset($parsedResponse['refresh_token'])){
                $this->setRefreshToken($parsedResponse['refresh_token']);
            }
    
            if(isset($parsedResponse['access_token'])){
                $this->setAccessToken($parsedResponse['access_token']);
            }

            $this->setGrantType($grantType);
        }
        
        return $response;
    }
    
    /**
     * Attempt an access token refresh
     * 
     * @param string $host Remote host
     * @param string $clientId Client id
     * @param string $clientSecret Client secret
     * 
     * @return boolean
     */
    public function refreshAccessToken(string $host, string $clientId, string $clientSecret){
        // Don't attempt to refresh the token if the refresh token is not available
        if(!$this->getRefreshToken()){
            return false;
        }

        // Request a new token
        $response = $this->httpClient->request('POST', $host . OAuth2Proxy::$REMOTE_TOKEN_ENDPOINT, [
            'body' => [
                'grant_type' => 'refresh_token',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $this->getRefreshToken(),
            ]
        ]);
        $parsedResponse = json_decode($response->getContent(false), true);

        // Erase session data
        $this->logout();

        if(isset($parsedResponse['refresh_token'])){
            $this->setRefreshToken($parsedResponse['refresh_token']);
        }
        
        if(isset($parsedResponse['access_token'])){
            $this->setAccessToken($parsedResponse['access_token']);

            // The access token has been updated
            return true;
        }

        return false;
    }

    /**
     * Clears all sessions attributes and refresh the session id
     * @return void
     */
    public function logout(){
        $this->session->clear();
        $this->csrf->generateCsrfToken(true);
    }
}
