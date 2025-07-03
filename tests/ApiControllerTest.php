<?php

namespace FullscreenInteractive\Restful\Tests;

use FullscreenInteractive\Restful\Controllers\ApiController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Dev\SapphireTest;

class ApiControllerTest extends SapphireTest
{
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
