<?php

namespace Wiselyst\OAuth2Proxy;

use Exception;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Josantonius\MimeType\MimeType;

class OAuth2Proxy{

    protected const ALLOWED_GRANT_TYPES = ['authorization_code', 'refresh_token'];

    protected const OVERRIDE_MIME_CONTENT_TYPE = [
        'css' => 'text/css',
        'js'  => 'application/javascript'
    ];

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
     * HttpClient
     * @var HttpClientInterface
     */
    protected $httpClient;

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
        $this->session = new Session();
        $this->httpClient = HttpClient::create();

        $this->authentication = new Authentication($this->httpClient);


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
        // Verify state
        $state = $this->session->get('state');

        if(strlen($state) === 0 && $state !== $this->request->query->get('state')){
            throw new Exception('Invalid state argument');
        }
        
        // Auth code -> token
        $response = $this->httpClient->request('POST', $this->apiHost . '/oauth/token', [
            'body' => [
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $this->apiHost . '/callback',
                'code' => $this->request->query->get('code')
            ]
        ]);
        
        $parsedResponse = json_decode($response, true);
        
        if(isset($parsedResponse['access_token'])){
            $this->authentication->setAccessToken($parsedResponse['access_token']);
        }

        if(isset($parsedResponse['refresh_token'])){
            $this->authentication->setAccessToken($parsedResponse['refresh_token']);
        }

        header('location: ' . $this->request->getUri());
        exit();
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
            if($this->authentication->renewAccessToken($this->apiHost, $this->clientId, $this->clientSecret) || true){ // FIXME:
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
        $route = str_replace(['../', './'], '', $this->request->getPathInfo());

        if($this->authentication->isAuthorized() || true){
            if(is_file($this->spaIndex . '/' . $route)){

                $extension = (pathinfo($this->spaIndex . '/' . $route))['extension'];
                if(in_array($extension, self::OVERRIDE_MIME_CONTENT_TYPE)){
                    header("Content-Type: " . self::OVERRIDE_MIME_CONTENT_TYPE[$extension]);
                }else{
                    header("Content-Type: " . mime_content_type($this->spaIndex . '/' . $route));
                }
                readfile($this->spaIndex . '/' . $route);
                exit;
            }else{
                if(is_file($this->spaIndex . '/index.html')){
                    header("Content-Type: " . mime_content_type($this->spaIndex . '/' . $route));
                    readfile($this->spaIndex . '/index.html');
                    exit;
                }else{
                    http_response_code(404);
                    exit;
                }
            }
            
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
            }

            // API proxy
            if(substr($route, 0, 5) === '/api/'){
                $this->handleApiProxy();
            }

            // SPA proxy
            $this->handleSpaProxy();
        }
    }
}