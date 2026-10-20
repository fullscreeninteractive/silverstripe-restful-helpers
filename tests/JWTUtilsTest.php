<?php

namespace FullscreenInteractive\Restful\Tests;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Level51\JWTUtils\JWTUtils;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;

class JWTUtilsTest extends SapphireTest
{
    private const SECRET = 'test-secret';

    protected function setUp(): void
    {
        parent::setUp();

        Config::modify()->set(JWTUtils::class, 'secret', self::SECRET);
        Config::modify()->set(JWTUtils::class, 'renew_threshold_in_minutes', 60);
    }

    protected function tearDown(): void
    {
        JWTUtils::tearDown();
        parent::tearDown();
    }

    public function testCheckReturnsTrueForValidToken()
    {
        $token = JWT::encode([
            'memberId' => 1,
            'exp' => time() + 3600,
            'rat' => time(),
        ], self::SECRET, 'HS256');

        $this->assertTrue(JWTUtils::inst()->check($token));
    }

    public function testCheckReturnsFalseForInvalidToken()
    {
        $this->assertFalse(JWTUtils::inst()->check('not-a-token'));
    }

    public function testRenewReturnsSameTokenWhenWithinThreshold()
    {
        $token = JWT::encode([
            'memberId' => 1,
            'exp' => time() + 3600,
            'rat' => time() - (20 * 60),
        ], self::SECRET, 'HS256');

        $this->assertSame($token, JWTUtils::inst()->renew($token));
    }

    public function testRenewReturnsUpdatedTokenWhenThresholdExceeded()
    {
        $oldRat = time() - (120 * 60);
        $oldExp = time() + 100;
        $token = JWT::encode([
            'memberId' => 1,
            'exp' => $oldExp,
            'rat' => $oldRat,
        ], self::SECRET, 'HS256');

        $renewed = JWTUtils::inst()->renew($token);

        $this->assertNotSame($token, $renewed);

        $decoded = (array) JWT::decode($renewed, new Key(self::SECRET, 'HS256'));

        $this->assertGreaterThan($oldRat, $decoded['rat']);
        $this->assertGreaterThan($oldExp, $decoded['exp']);
    }
}
