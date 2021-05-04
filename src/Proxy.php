<?php

namespace Wiselyst\OAuth2Proxy;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

class Proxy{

    /**
     * Server request
     * @var Request
     */
    protected $serverRequest;
 
    /**
     * Request to proxy
     * @var Request
     */
    protected $proxyRequest;

    /**
     * Proxy path info
     * @var string
     */
    protected $proxyPathInfo;

    /**
     * Authorization header
     * @var array
     */
    protected $authorizationHeader = [];

    /**
     * Server host
     * @var string
     */
    protected $serverHost;

    /**
     * Server host
     * @var HttpClientInterface
     */
    protected $client;

    /**
     * Headers to skip when returning server response
     * @var array
     */
    protected const SKIP_HEADERS = ['transfer-encoding', 'date', 'host', 'connection', 'HOST', 'content-encoding'];

    public function __construct(string $serverHost, HttpClientInterface $httpClient, Request $request){
        $this->serverHost = $serverHost;

        $this->client = $httpClient; HttpClient::create();
        $this->serverRequest = $request;
        $this->proxyRequest = $this->serverRequest;
        $this->proxyPathInfo = $this->serverRequest->getPathInfo();
    }

    /**
     * Get proxy path info
     * @see Symfony\Component\HttpFoundation\Request@getPathInfo
     * @return string
     */
    public function getProxyPathInfo(){
        return $this->proxyPathInfo;
    }

    /**
     * Set proxy path info
     * @see Symfony\Component\HttpFoundation\Request@getPathInfo
     * @return string
     */
    public function setProxyPathInfo(string $pathInfo){
        $this->proxyPathInfo = $pathInfo;
    }

    /**
     * Run a proxy request
     * @return ResponseInterface
     */
    public function run() : ResponseInterface{
        // Remove skip headers
        $requestHeaders = $this->serverRequest->server->getHeaders();
        foreach ($requestHeaders as $key => $value){
            if(in_array($key, self::SKIP_HEADERS)){
                unset($requestHeaders[$key]);
            }
        }

        $response = $this->client->request($this->serverRequest->getMethod(), $this->serverHost . $this->getProxyPathInfo(), [
            'headers' => array_merge(
                $requestHeaders,
                $this->authorizationHeader
            ),
            'body' => count($this->serverRequest->request->all()) !== 0 ? $this->serverRequest->request->all() : $this->serverRequest->getContent(),
            'query' => $this->serverRequest->query->all()
        ]);

        $response->getContent(false); // This is to not throw an exception in case of an response error

        return $response;
    }

    /**
     * Add authorization header to proxy request
     * @return self
     */
    public function setAuthorization(string $value){
        $this->authorizationHeader = ['Authorization' => $value];
    }

    /**
     * Emit a ResponseInterface from the run() method
     * 
     * @param ResponseInterface $response
     * @return void
     */
    public static function dispatch(ResponseInterface $response){
        // Set response headers
        foreach ($response->getHeaders(false) as $name => $values) {
            if(!in_array(strtolower($name), self::SKIP_HEADERS)){
                foreach($values as $value){
                    header(sprintf('%s: %s', $name, $value));
                }
            }
        }

        // Set the response code
        http_response_code($response->getStatusCode());

        // Output content
        echo $response->getContent(false);
        exit();
    }


}
