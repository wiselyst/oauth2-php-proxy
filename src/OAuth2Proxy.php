<?php

namespace Wiselyst\OAuth2Proxy;

use Exception;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use League\MimeTypeDetection\ExtensionMimeTypeDetector;
class OAuth2Proxy{

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
     * HttpClient
     * @var HttpClientInterface
     */
    protected $httpClient;

    /**
     * Request
     * @var Request
     */
    protected $request;

    public function __construct(){
        // Initialize dependencies
        $this->session = new Session();
        $this->httpClient = HttpClient::create();
        $this->authentication = new Authentication($this->httpClient, $this->session);

        // Start sessions
        if(!$this->session->isStarted()){
            $this->session->start();
        }

        // Create request from globals
        $this->request = Request::createFromGlobals();
    }

    
    //----------------------------------------------
    // AUTHENTICATION
    //----------------------------------------------

    /**
     * API server host
     * @var string
     */
    protected $apiHost;

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
     * Scope
     * @var string
     */
    protected $scope = "";

    /**
     * Set API host
     * @param string apiHost API Server host (eg. http://api.localhost:1234)
     * @return void
     */
    public function setApiHost(string $apiHost): void{
        $this->apiHost = $apiHost;
    }

    /**
     * Set client credentials
     * @param string $clientId Client id
     * @param string $clientSecret Client secret
     * @return void
     */
    public function setClientCredentials(string $clientId, string $clientSecret = ""): void{
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Set scope
     * @param string $scope Scope
     * @return void
     */
    public function setScope(string $scope): void{
        $this->scope = $scope;
    }


    //----------------------------------------------
    // SPA
    //----------------------------------------------

    /**
     * SPA directory
     * @var string
     */
    protected $spaDir = null;

    /**
     * Require authentication for SPA
     * @var bool
     */
    protected $requireAuthentication = false;

    /**
     * Set SPA directory
     * @param string $spaDir
     * @return void
     */
    public function setSpaDir(string $spaDir): void{
        $this->spaDir = $spaDir;
    }

    /**
     * Require SPA Authentication
     * @param bool $require
     * @return void
     */
    public function requireAuthentication(bool $require = true){
        $this->requireAuthentication = $require;
    }

    //----------------------------------------------
    // GRANT TYPE
    //----------------------------------------------

    /**
     * Supported grant types
     * @var string[]
     */
    protected const ALLOWED_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials', 'password'];

    /**
     * Enabled grant types
     * @var string[]
     */
    private $enabledGrantTypes = [];

    /**
     * Enable grant type
     * @param string $grantType
     * @return void
     */
    public function enableGrantType(string $grantType): void{
        if($grantType === 'authorization_code' && ($this->isGrantTypeEnabled('client_credentials') || $this->isGrantTypeEnabled('password'))){
            throw new \Exception('Unable to enable grant type "' . $grantType . '" while "client_credentials" or "password" is enabled');
        }

        if(($grantType === 'client_credentials' || $grantType === 'password') && $this->isGrantTypeEnabled('authorization_code')){
            throw new \Exception('Unable to enable grant type "' . $grantType . '" while "authorization_code"');
        }

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
     * @return void
     */
    public function disableGrantType(string $grantType): void{
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

    //----------------------------------------------
    // OAUTH2 FLOW METHODS
    //----------------------------------------------

    /**
     * Endpoint for token and access_token requests
     * @var string
     */
    public const REMOTE_TOKEN_ENDPOINT = '/token';

    /**
     * Endpoint for authorization code redirect
     * @var string
     */
    public const REMOTE_AUTHORIZE_ENDPOINT = '/authorize';

    /**
     * Handle Authorization Code redirect request
     * @return void
     */
    public function handleAuthorizationCodeRedirect(): void{
        $this->session->set('state', $state = sha1(uniqid("", true)));

        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->request->getSchemeAndHttpHost() . $this->request->getBasePath() . '/callback',
            'response_type' => 'code',
            'scope' => $this->scope,
            'state' => $state,
        ]);

        header('location: ' . $this->apiHost . self::REMOTE_AUTHORIZE_ENDPOINT . '?' . $query);
        exit();
    }

    /**
     * Handle Authorization Code callback request
     * @return void
     */
    public function handleAuthorizationCodeCallback(){
        // Verify state
        $state = $this->session->get('state');

        if(strlen($state) === 0 && $state !== $this->request->query->get('state')){
            throw new Exception('Invalid state argument');
        }

        // Logout
        $this->authentication->logout();
        
        // Auth code -> token
        $response = $this->httpClient->request('POST', $this->apiHost . self::REMOTE_TOKEN_ENDPOINT, [
            'body' => [
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $this->request->getSchemeAndHttpHost() . $this->request->getBasePath() . '/callback',
                'code' => $this->request->query->get('code')
            ]
        ]);

       $parsedResponse = json_decode($response->getContent(false), true);
        
        if(isset($parsedResponse['refresh_token'])){
            $this->authentication->setAccessToken($parsedResponse['refresh_token']);
        }

        if(isset($parsedResponse['access_token'])){
            $this->authentication->setAccessToken($parsedResponse['access_token']);
            header('location: ' . $this->request->getSchemeAndHttpHost() . $this->request->getBasePath());
            exit();
        }
        
        Proxy::dispatch($response);
    }

    /**
     * Handle API Requests
     * @return void
     */
    protected function handleApiProxy(){
        $proxy = new Proxy($this->apiHost, $this->httpClient, $this->request);
        $pathInfo = $proxy->getProxyPathInfo();
        if(substr($pathInfo, 0, 5) === '/api/'){
            $proxy->setProxyPathInfo(
                substr($pathInfo, 4)
            );
        }
        

        if($this->authentication->getAccessToken()){
            $proxy->setAuthorization('Bearer ' . $this->authentication->getAccessToken());
        }else{
            if($this->isGrantTypeEnabled('client_credentials')){
                // Attempt to get a token
                $this->authentication->requestAccessToken($this->apiHost, 'client_credentials', $this->clientId, $this->clientSecret);
        
                if($this->authentication->getAccessToken()){
                    $proxy->setAuthorization('Bearer ' . $this->authentication->getAccessToken());
                }
            }
        }
    
        $response = $proxy->run();
    
        if($response->getStatusCode() === 401 && $this->isGrantTypeEnabled('refresh_token')){
            // Try to renew token   
            if($this->authentication->refreshAccessToken($this->apiHost, $this->clientId, $this->clientSecret)){
                $proxy->setAuthorization('Bearer ' . $this->authentication->getAccessToken());
            }
            $response = $proxy->run();
            if($response->getStatusCode() === 401){
                $this->authentication->logout();
            }
        }
    
        Proxy::dispatch($response);
        exit();
    }

    /**
     * Handle SPA requests
     * @return void
     */
    protected function handleSpaProxy(){
        if($this->spaDir === null){
            throw new Exception("Unable to process a SPA proxy request, single page application directory is not set");
        }

        $route = str_replace(['../', './'], '', $this->request->getPathInfo());

        if($this->requireAuthentication && !$this->authentication->getAccessToken()){
            if($this->isGrantTypeEnabled('authorization_code')){
                $this->handleAuthorizationCodeRedirect();
            }
            throw new Exception('Authorization required');
            exit;
        }

        if(is_file($this->spaDir . '/' . $route)){
            $detector = new ExtensionMimeTypeDetector();
            header("Content-Type: " . $detector->detectMimeTypeFromFile($this->spaDir . '/' . $route));
            readfile($this->spaDir . '/' . $route);
            exit;
        }else{
            if(is_file($this->spaDir . '/index.html')){
                header("Content-Type: text/html");
                readfile($this->spaDir . '/index.html');
                exit;
            }else{
                http_response_code(404);
                exit;
            }
        }        
    }

    public function handleTokenRequest(){
        // Grant type
        $grantType = $this->request->request->get('grant_type');
        if(!$this->isGrantTypeEnabled($grantType)){
            throw new Exception("Invalid grant type");
        }

        // Get username and password from body
        $username = '';
        $password = '';
        if($grantType === 'password'){
            $username = $this->request->request->get('username') ?? '';
            $password = $this->request->request->get('password') ?? '';
        }

        // Request access token
        $tokenRequest = $this->authentication->requestAccessToken(
            $this->apiHost,
            $grantType,
            $this->clientId,
            $this->clientSecret,
            $username,
            $password
        );

        if($tokenRequest->getStatusCode() === 200){
            // Hide token on success response
            $this->dispatchJSONResponse([
                'status' => true,
                'message' => 'Authenticated'
            ]);
        }

        // Return server response if the request was not successful
        $this->dispatchJSONResponse(json_decode($tokenRequest->getContent(false), true), $tokenRequest->getStatusCode());
    }


    /**
     * Dispatch a JSON Response
     * @param array $data Response content
     * @param int $status HTTP Status code
     */
    protected function dispatchJSONResponse(array $data, int $status = 200){
        header("Content-Type: application/json");
        http_response_code($status);
        echo json_encode($data);
        exit();
    }

    /**
     * Run the proxy
     * @return void
     */
    public function run(){
        $route = $this->request->getPathInfo();

        // Authorization code callback
        if($route === '/callback' && $this->isGrantTypeEnabled('authorization_code')){
            $this->handleAuthorizationCodeCallback();
        }

        // Authorization code redirect
        if($route === '/redirect' && $this->isGrantTypeEnabled('authorization_code')){
            $this->handleAuthorizationCodeRedirect();
        }

        // Handle token request
        if($route === '/token' && ($this->isGrantTypeEnabled('client_credentials') || $this->isGrantTypeEnabled('password')) ){
            $this->handleTokenRequest();
        }

        // API proxy
        if(substr($route, 0, 5) === '/api/'){
            $this->handleApiProxy();
        }

        // SPA proxy
        $this->handleSpaProxy();
    }
}