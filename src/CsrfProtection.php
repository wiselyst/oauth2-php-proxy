<?php

namespace Wiselyst\OAuth2Proxy;

use Exception;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Request;

class CsrfProtection{

    /**
     * @var Session
     */
    private $session;

    /**
     * Request
     * @var Request
     */
    protected $request;

    public function __construct(SessionInterface $session, Request $request){
        $this->session = $session;
        $this->request = $request;
    }

    /**
     * Generate a new CSRF Token
     *
     * @param boolean $force
     * @return void
     */
    public function generateCsrfToken($force = false): void{
        $sessionToken = $this->session->get('XSRF-TOKEN');

        if($sessionToken === null || !isset($_COOKIE['XSRF-TOKEN']) || $force){
            $sessionToken = base64_encode(openssl_random_pseudo_bytes(128));
            $this->session->set('XSRF-TOKEN', $sessionToken);
            
            if(isset($_COOKIE['XSRF-TOKEN'])){
                unset($_COOKIE['XSRF-TOKEN']);
            }

            setcookie("XSRF-TOKEN", $sessionToken, [
                'path' => '/'
            ]);
        }
    }

    /**
     * Validate a CSRF token
     *
     * @param boolean $throwException
     * @return boolean
     */
    public function validateCsrfToken($throwException = false): bool{
        $headerToken = $this->request->headers->get('X-CSRF-TOKEN');
        $sessionToken = $this->session->get('XSRF-TOKEN');
        if($headerToken !== null && $sessionToken !== null && $headerToken === $sessionToken){
            return true;
        }

        if($throwException){
            throw new Exception("X-XSRF-TOKEN header invalid or not present in request");
        }

        return false;
    }
}
