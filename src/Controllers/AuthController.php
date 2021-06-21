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
}
