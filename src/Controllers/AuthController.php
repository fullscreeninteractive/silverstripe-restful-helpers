<?php

namespace FullscreenInteractive\Restful\Controllers;

use Level51\JWTUtils\JWTUtils;
use Level51\JWTUtils\JWTUtilsException;

class AuthController extends ApiController
{
    private static $allowed_actions = [
        'token',
        'verify',
    ];

    private static $test = '123';

    /**
     * The token is acquired by using basic auth. Once the user has entered the
     * username / password and completed this first step then we give them back
     * a token which contains their information
     */
    public function token() {
        try {
            $payload = JWTUtils::inst()->byBasicAuth($this->request);

            return $this->returnArray($payload);
        } catch (JWTUtilsException $e) {
            return $this->httpError(403, $e->getMessage());
        }
    }

    /**
     * Verifies a token is valid
     */
    public function verify()
    {
        if ($jwt = $this->getJwt()) {
            return $this->returnArray(
                ['token' => $jwt]
            );
        }
    }

    public function getJwt()
    {
        $bearer = $this->getBearerToken();

        if (!$bearer) {
            return $this->httpError(401);
        }

        if (!JWTUtils::inst()->check($bearer)) {
            return $this->httpError(401);
        }

        $jwt = JWTUtils::inst()->renew($bearer);

        if (!$jwt) {
            return $this->httpError(401);
        }

        return $jwt;
    }

    public function getAuthorizationHeader(): string
    {
        $header = '';

        if (isset($_SERVER['Authorization'])) {
            $header = trim($_SERVER["Authorization"]);
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));

            if (isset($requestHeaders['Authorization'])) {
                $header = trim($requestHeaders['Authorization']);
            }
        }

        return $header;
    }

    public function getBearerToken(): string
    {
        $headers = $this->getAuthorizationHeader();

        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }

        return '';
    }

}
