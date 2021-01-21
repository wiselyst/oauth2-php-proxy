<?php

namespace Wiselyst\OAuth2Proxy;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;

class OAuth2Proxy{

    protected const ALLOWED_GRANT_TYPES = ['authorization_code', 'refresh_token'];

    /**
     * Enabled grant types
     * @var array
     */
    private $enabledGrantTypes = [];

    /**
     * Authentication
     * @var Authentication
     */
    protected $authentication;

    /**
     * Session
     * @var Session
     */
    protected $session;

    /**
     * API server host
     * @var string
     */
    protected $apiHost;

    /**
     * SPA index file
     * @var string
     */
    protected $spaIndex = 'index.html';

    /**
     * Request
     * @var Request
     */
    protected $request;

    /**
     * Client ID
     * @var string
     */
    protected $clientId = "";

     /**
     * Client secret
     * @var string
     */
    protected $clientSecret = "";

    /**
     * Redirect URI
     * @var string
     */
    protected $redirectUri = "";

    /**
     * Scope
     * @var string
     */
    protected $scope = "";

    public function __construct(){
        $this->authentication = new Authentication();
        $this->session = new Session();

        if(!$this->session->isStarted()){
            $this->session->start();
        }

        $this->request = Request::createFromGlobals();
    }

    public function setClientCredentials($clientId, $clientSecret = ""){
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    public function setScope(string $scope){
        $this->scope = $scope;
    }

    /**
     * Set API host
     * @param string apiHost API Server host (eg. http://api.localhost:1234)
     */
    public function setApiHost(string $apiHost){
        $this->apiHost = $apiHost;
    }

    /**
     * Set SPA index
     * @param string $spaIndex
     */
    public function setSpaIndex(string $spaIndex){
        $this->spaIndex = $spaIndex;
    }

    /**
     * Enable grant type
     * @param string $grantType
     */
    public function enableGrantType(string $grantType){
        if(in_array($grantType, self::ALLOWED_GRANT_TYPES)){
            if(!$this->isGrantTypeEnabled($grantType)){
                $this->enabledGrantTypes[] = $grantType;
            }
            return;
        }

        throw new \Exception('Unsupported grant type "' . $grantType . "");
    }

    /**
     * Disable grant type
     * @param string $grantType
     */
    public function disableGrantType(string $grantType){
        if(in_array($grantType, self::ALLOWED_GRANT_TYPES) && $this->isGrantTypeEnabled($grantType)){
            unset($this->enabledGrantTypes[$grantType]);
        }
        return;
    }

    /**
     * Check whether a grant type is enabled or not
     * @param string $grantType
     * @return bool
     */
    public function isGrantTypeEnabled(string $grantType) : bool{
        return in_array($grantType, $this->enabledGrantTypes);
    }

    /**
     * Handle Authorization Code redirect request
     * @return void
     */
    public function handleAuthorizationCodeRedirect(){
        $this->session->set('state', $state = sha1(uniqid("", true)));

        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->request->getBaseUrl() . '/callback',
            'response_type' => 'code',
            'scope' => $this->scope,
            'state' => $state,
        ]);

        header('location: ' . $this->apiHost . '/oauth/authorize?' . $query);
        exit();
    }

    /**
     * Handle Authorization Code callback request
     * @return void
     */
    public function handleAuthorizationCodeCallback(){

    }

    /**
     * Handle API Requests
     * @return void
     */
    protected function handleApiProxy(){
        $proxy = new Proxy($this->apiHost);

        if($this->authentication->getAccessToken()){
            $proxy->setAuthorization('Bearer ' . $this->authentication->getAccessToken());
        }
    
        $response = $proxy->run();
    
        if($response->getStatusCode() === 401 && $this->isGrantTypeEnabled('refresh_token')){
            // Try to renew token   
            if($this->authentication->renewAccessToken() || true){ // FIXME:
                $proxy->setAuthorization('Bearer ' . $this->authentication->getAccessToken());
            }
            $response = $proxy->run();
            if($response->getStatusCode() === 401){
                $this->authentication->logout();
            }
        }
    
        $proxy->dispatch($response);
    }

    /**
     * Handle SPA requests
     * @return void
     */
    protected function handleSpaProxy(){
        if($this->authentication->isAuthorized()){
            if(is_file($this->spaIndex)){
                echo file_get_contents($this->spaIndex);
                return;
            }
            
            http_response_code(404);
        }
    }

    /**
     * Run the proxy
     * @return void
     */
    public function run(){
        if($this->isGrantTypeEnabled('authorization_code')){

            $route = $this->request->getPathInfo();

            // Authorization code callback
            if($route === '/callback'){
                $this->handleAuthorizationCodeCallback();
                return;
            }

            // API proxy
            if(substr($route, 0, 5) === '/api/'){
                $this->handleApiProxy();
                return;
            }

            // SPA proxy
            $this->handleSpaProxy();
        }
    }
}