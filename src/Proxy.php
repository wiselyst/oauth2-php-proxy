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
    protected const SKIP_HEADERS = ['transfer-encoding', 'date', 'host', 'connection'];

    public function __construct(string $serverHost, HttpClientInterface $httpClient, Request $request){
        $this->serverHost = $serverHost;

        $this->client = $httpClient; HttpClient::create();
        $this->serverRequest = $request; //Request::createFromGlobals();
        $this->proxyRequest = $this->serverRequest;
    }

    public function run() : ResponseInterface{

        $body = count($this->serverRequest->request->all()) !== 0 ? $this->serverRequest->request->all() : $this->serverRequest->getContent();
        
        $response = $this->client->request($this->serverRequest->getMethod(), $this->serverHost . $this->serverRequest->getPathInfo(), [
            'headers' => array_merge(
                $this->serverRequest->server->getHeaders(),
                $this->authorizationHeader
            ),
            'body' => $body,
            'query' => $this->serverRequest->query->all()
        ]);

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
     * Emit ResponseInterface
     * @param ResponseInterface $response
     * @return void
     */
    public static function dispatch(ResponseInterface $response){
        ob_clean();

        // Headers
        foreach ($response->getHeaders(false) as $name => $values) {
            if(!in_array(strtolower($name), self::SKIP_HEADERS)){
                foreach($values as $value){
                    header(sprintf('%s: %s', $name, $value));
                }
            }
        }

        // Status code
        http_response_code($response->getStatusCode());

        // Content
        echo $response->getContent(false);
        exit();
    }


}