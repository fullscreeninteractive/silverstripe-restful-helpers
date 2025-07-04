<?php

namespace FullscreenInteractive\Restful\Controllers;

use Level51\JWTUtils\JWTUtils;
use Level51\JWTUtils\JWTUtilsException;
use SilverStripe\Model\ArrayData;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class AuthController extends ApiController
{
    private static $allowed_actions = [
        'token',
        'verify',
    ];

    /**
     * The token is acquired by using basic auth. Once the user has entered the
     * username / password and completed this first step then we give them back
     * a token which contains their information
     */
    public function token()
    {
        try {
            $payload = JWTUtils::inst()->byBasicAuth($this->request, true);

            if (isset($payload['member']['id'])) {
                $member = Member::get()->byID($payload['member']['id']);

                if ($member) {
                    $api = [];

                    if ($member->hasMethod('toApi')) {
                        $api = $member->toApi() ?? [];

                        if ($api instanceof ArrayData) {
                            $api = $api->toMap();
                        }
                    }

                    $payload['member'] = array_merge($payload['member'], $api);
                }

                return $this->returnArray($payload);
            }

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
            $verifyResponse = [
                'token' => $jwt
            ];

            $this->invokeWithExtensions('onVerify', $verifyResponse);

            return $this->returnArray($verifyResponse);
        }
    }
}
