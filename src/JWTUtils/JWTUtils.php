<?php

namespace Level51\JWTUtils;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\BasicAuth;

class JWTUtils
{
    /**
     * @var int
     */
    private static $lifetime_in_days = 7;

    /**
     * @var int
     */
    private static $renew_threshold_in_minutes = 60;

    /**
     * @var JWTUtils|null
     */
    private static $instance = null;

    /**
     * @return JWTUtils
     * @throws JWTUtilsException
     */
    public static function inst()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function tearDown()
    {
        self::$instance = null;
    }

    /**
     * @throws JWTUtilsException
     */
    private function __construct()
    {
        if (!$this->hasValidSecret()) {
            throw new JWTUtilsException('No "secret" config found.');
        }
    }

    private function __clone()
    {
    }

    private function hasValidSecret()
    {
        return (bool) Injector::inst()->convertServiceProperty(Config::inst()->get(self::class, 'secret'));
    }

    private function calcExpirationClaim()
    {
        $days = (int) Config::inst()->get(self::class, 'lifetime_in_days');
        return time() + ($days * 24 * 60 * 60);
    }

    public function getClaims()
    {
        return [
            'iss' => Config::inst()->get(self::class, 'iss') ?: Director::absoluteBaseURL(),
            'exp' => $this->calcExpirationClaim(),
            'iat' => time(),
            'rat' => time(),
            'jti' => bin2hex(random_bytes(16))
        ];
    }

    /**
     * @throws JWTUtilsException
     */
    public function byBasicAuth($request, $includeMemberData = true)
    {
        try {
            $member = BasicAuth::requireLogin($request, null, null, false);
        } catch (HTTPResponse_Exception $e) {
            throw new JWTUtilsException($e->getResponse()->getBody());
        }

        $token = JWT::encode(
            array_merge([
                'memberId' => $member->ID
            ], $this->getClaims()),
            Config::inst()->get(self::class, 'secret'),
            'HS256'
        );

        $payload = [
            'token' => $token
        ];

        if ($includeMemberData) {
            $payload['member'] = [
                'id' => $member->ID,
                'email' => $member->Email,
                'firstName' => $member->FirstName,
                'surname' => $member->Surname
            ];
        }

        return $payload;
    }

    /**
     * @throws JWTUtilsException
     */
    public function renew($token)
    {
        try {
            $jwt = (array) JWT::decode(
                $token,
                new Key(
                    Config::inst()->get(self::class, 'secret'),
                    'HS256'
                )
            );
        } catch (\Exception $e) {
            throw new JWTUtilsException($e->getMessage());
        }

        $renewedAt = isset($jwt['rat']) ? (int) $jwt['rat'] : 0;
        $renewAgeMinutes = (time() - $renewedAt) / 60;

        if ($renewAgeMinutes < (int) Config::inst()->get(self::class, 'renew_threshold_in_minutes')) {
            return $token;
        }

        $jwt['exp'] = $this->calcExpirationClaim();
        $jwt['rat'] = time();

        return JWT::encode(
            $jwt,
            Config::inst()->get(self::class, 'secret'),
            'HS256'
        );
    }

    public function check($token)
    {
        try {
            JWT::decode(
                $token,
                new Key(
                    Config::inst()->get(self::class, 'secret'),
                    'HS256'
                )
            );
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}
