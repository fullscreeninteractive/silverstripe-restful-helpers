<?php

namespace FullscreenInteractive\Restful\Tests;

use FullscreenInteractive\Restful\Controllers\ApiController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Dev\SapphireTest;

class ApiControllerTests extends SapphireTest
{
    public function testGetVar()
    {
        $api = new ApiController();
        $api->setRequest(new HTTPRequest('GET', '/api/', [
            'foo' => 1
        ]));

        $this->assertEquals(1, $api->getVar('foo'));
        $this->assertNull($api->getVar('bar'));
    }
}
