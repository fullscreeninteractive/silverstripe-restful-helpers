<?php

namespace FullscreenInteractive\Restful\Tests;

use FullscreenInteractive\Restful\Auth\JWTUtils;
use FullscreenInteractive\Restful\Controllers\ApiController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class ApiControllerTest extends SapphireTest
{
    protected $usesDatabase = true;

    protected function setUp(): void
    {
        parent::setUp();

        JWTUtils::tearDown();
        Config::modify()->set(JWTUtils::class, 'secret', 'test-secret-that-is-at-least-32-bytes-long');
    }

    protected function tearDown(): void
    {
        JWTUtils::tearDown();
        parent::tearDown();
    }

    private function createApi(?string $authorization = null, array $headers = []): ApiController
    {
        $request = (new HTTPRequest('GET', '/api/'))->setSession(new Session([]));

        if ($authorization) {
            $request->addHeader('Authorization', $authorization);
        }

        foreach ($headers as $name => $value) {
            $request->addHeader($name, $value);
        }

        $api = ApiController::create();
        $api->handleRequest($request);

        return $api;
    }

    private function assertHttpError(int $code, callable $callback): void
    {
        try {
            $callback();
            $this->fail('Expected HTTP ' . $code);
        } catch (HTTPResponse_Exception $e) {
            $this->assertSame($code, $e->getResponse()->getStatusCode());
        }
    }

    private function createMember(): Member
    {
        $member = Member::create(['Email' => 'api@example.com']);
        $member->write();

        return $member;
    }

    public function testEnsureUserLoggedInWithValidToken()
    {
        $member = $this->createMember();
        $token = JWTUtils::inst()->createTokenForMember($member);
        $api = $this->createApi('Bearer ' . $token);

        // Actions run while their controller is current
        $api->pushCurrent();

        try {
            $this->assertSame($member->ID, $api->ensureUserLoggedIn()->ID);
            $this->assertSame($member->ID, Security::getCurrentUser()->ID);
            $this->assertSame($token, $api->getJwt());
        } finally {
            $api->popCurrent();
        }

        // A bearer token must not create a session login
        $this->assertNull($api->getRequest()->getSession()->get('loggedInAs'));
    }

    public function testEnsureUserLoggedInRequiresToken()
    {
        $api = $this->createApi();

        $this->assertHttpError(401, fn () => $api->ensureUserLoggedIn());
    }

    public function testEnsureUserLoggedInRejectsInvalidToken()
    {
        $api = $this->createApi('Bearer not-a-token');

        $this->assertHttpError(401, fn () => $api->ensureUserLoggedIn());
    }

    public function testEnsureUserLoggedInRejectsDeletedMember()
    {
        $member = $this->createMember();
        $token = JWTUtils::inst()->createTokenForMember($member);
        $member->delete();

        $api = $this->createApi('Bearer ' . $token);

        $this->assertHttpError(401, fn () => $api->getJwt());
    }

    public function testEnsureUserLoggedInRejectsLockedOutMember()
    {
        $member = $this->createMember();
        $token = JWTUtils::inst()->createTokenForMember($member);
        $member->LockedOutUntil = date('Y-m-d H:i:s', DBDatetime::now()->getTimestamp() + 3600);
        $member->write();

        $api = $this->createApi('Bearer ' . $token);

        $this->assertHttpError(401, fn () => $api->ensureUserLoggedIn());
    }

    public function testEnsureUserLoggedInWithoutPermissionIsForbidden()
    {
        $member = $this->createMember();
        $api = $this->createApi('Bearer ' . JWTUtils::inst()->createTokenForMember($member));

        $this->assertHttpError(403, fn () => $api->ensureUserLoggedIn(['ADMIN']));
    }

    public function testInvalidJsonIsRejected()
    {
        $request = (new HTTPRequest('POST', '/api/', [], [], '{"foo":'))->setSession(new Session([]));
        $request->addHeader('Content-Type', 'application/json');

        $response = ApiController::create()->handleRequest($request);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringContainsString('Invalid JSON', $response->getBody());
    }

    public function testJsonBodyIsParsed()
    {
        $request = (new HTTPRequest('POST', '/api/', [], [], '{"Foo":"bar"}'))->setSession(new Session([]));
        $request->addHeader('Content-Type', 'application/json');

        $api = ApiController::create();
        $api->handleRequest($request);

        $this->assertSame('bar', $api->getVar('foo'));
    }

    public function testCorsAllowsConfiguredOriginsOnly()
    {
        Config::modify()->set(ApiController::class, 'allowed_origins', ['https://app.example.com']);

        $api = $this->createApi(null, ['Origin' => 'https://app.example.com']);
        $this->assertSame(
            'https://app.example.com',
            $api->getResponse()->getHeader('Access-Control-Allow-Origin')
        );

        $api = $this->createApi(null, ['Origin' => 'https://evil.example.com']);
        $this->assertNull($api->getResponse()->getHeader('Access-Control-Allow-Origin'));
    }
    public function testGetVar()
    {
        $api = ApiController::create();
        $api->handleRequest((new HTTPRequest('GET', '/api/', [
            'foo' => 1
        ]))->setSession(new Session([])));

        $this->assertEquals(1, $api->getVar('foo'));
        $this->assertNull($api->getVar('bar'));
    }

    public function testHasVar()
    {
        $api = ApiController::create();
        $api->handleRequest((new HTTPRequest('GET', '/api/', [
            'foo' => 1
        ]))->setSession(new Session([])));

        $this->assertTrue($api->hasVar('foo'));
        $this->assertFalse($api->hasVar('bar'));
    }

    public function testEnsureVars()
    {
        $api = ApiController::create();

        $api->handleRequest((new HTTPRequest('GET', '/api/', [
            'foo' => 1
        ]))->setSession(new Session([])));

        list($foo) = $api->ensureVars([
            'foo'
        ]);

        $this->assertEquals(1, $foo);
    }
}
