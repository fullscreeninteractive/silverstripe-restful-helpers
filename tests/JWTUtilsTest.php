<?php

namespace FullscreenInteractive\Restful\Tests;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use FullscreenInteractive\Restful\Auth\JWTUtils;
use FullscreenInteractive\Restful\Auth\JWTUtilsException;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;

class JWTUtilsTest extends SapphireTest
{
    private const SECRET = 'test-secret-that-is-at-least-32-bytes-long';

    protected function setUp(): void
    {
        parent::setUp();

        JWTUtils::tearDown();
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

    public function testCheckReturnsFalseForTokenSignedWithAnotherSecret()
    {
        $token = JWT::encode([
            'memberId' => 1,
            'exp' => time() + 3600,
        ], str_repeat('x', 32), 'HS256');

        $this->assertFalse(JWTUtils::inst()->check($token));
    }

    public function testCheckReturnsFalseForExpiredToken()
    {
        $token = JWT::encode([
            'memberId' => 1,
            'exp' => time() - 10,
        ], self::SECRET, 'HS256');

        $this->assertFalse(JWTUtils::inst()->check($token));
    }

    public function testCheckReturnsFalseWithoutMemberId()
    {
        $token = JWT::encode([
            'exp' => time() + 3600,
        ], self::SECRET, 'HS256');

        $this->assertFalse(JWTUtils::inst()->check($token));

        $token = JWT::encode([
            'memberId' => 'admin',
            'exp' => time() + 3600,
        ], self::SECRET, 'HS256');

        $this->assertFalse(JWTUtils::inst()->check($token));
    }

    public function testRejectsShortSecret()
    {
        Config::modify()->set(JWTUtils::class, 'secret', 'short');

        $this->expectException(JWTUtilsException::class);
        JWTUtils::inst();
    }

    public function testRejectsMissingSecret()
    {
        Config::modify()->set(JWTUtils::class, 'secret', null);

        $this->expectException(JWTUtilsException::class);
        JWTUtils::inst();
    }

    public function testSecretResolvesEnvironmentVariable()
    {
        $envSecret = str_repeat('e', 40);
        Environment::setEnv('RESTFUL_HELPERS_TEST_JWT_SECRET', $envSecret);
        Config::modify()->set(JWTUtils::class, 'secret', '`RESTFUL_HELPERS_TEST_JWT_SECRET`');

        $token = JWTUtils::inst()->encode([
            'memberId' => 1,
            'exp' => time() + 3600,
        ]);

        $decoded = (array) JWT::decode($token, new Key($envSecret, 'HS256'));
        $this->assertSame(1, $decoded['memberId']);
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

    public function testRenewThrowsForInvalidToken()
    {
        $this->expectException(JWTUtilsException::class);
        JWTUtils::inst()->renew('not-a-token');
    }

    public function testMaxLifetimeCapsRenewal()
    {
        Config::modify()->set(JWTUtils::class, 'max_lifetime_in_days', 30);

        $iat = time() - (29 * 24 * 60 * 60);
        $token = JWT::encode([
            'memberId' => 1,
            'iat' => $iat,
            'exp' => time() + 100,
            'rat' => time() - (120 * 60),
        ], self::SECRET, 'HS256');

        $decoded = (array) JWT::decode(JWTUtils::inst()->renew($token), new Key(self::SECRET, 'HS256'));

        $this->assertSame($iat + (30 * 24 * 60 * 60), $decoded['exp']);
    }

    public function testMaxLifetimeRejectsOldTokens()
    {
        Config::modify()->set(JWTUtils::class, 'max_lifetime_in_days', 30);

        $token = JWT::encode([
            'memberId' => 1,
            'iat' => time() - (31 * 24 * 60 * 60),
            'exp' => time() + 3600,
        ], self::SECRET, 'HS256');

        $this->assertFalse(JWTUtils::inst()->check($token));
    }
}
