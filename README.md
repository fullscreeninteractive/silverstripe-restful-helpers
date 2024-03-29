# silverstripe-restful-helpers

Another module for providing some base functionality for a basic RESTFul JSON
API. While everyone seems to be jumping onto GraphQL, if all you need is a
quick setup with not too much configuration to get your head around, nothing
beats a simple REST solution.

Handles authenication and provides common functions for serving and parsing
API requests. Compared to `silverstripe-restfulserver` this module does very
little scaffolding of models and fields out of the box but instead relies on
developers to design the API layout (although scaffolding helpers are available)

## Installation

```
composer require fullscreeninteractive/silverstripe-restful-helpers
```

## Usage

If you plan on using Authenication for your API then you first need to config
the [https://github.com/Level51/silverstripe-jwt-utils/](JWTUtils) module.

_app/\_config/api.yml_

```yml
Level51\JWTUtils\JWTUtils:
  secret: 'replace-this-with-a-jwt-secret-for-jwt'
  lifetime_in_days: 365
  renew_threshold_in_minutes: 60
```

Next step is to setup the routing for the API. You can modify the name of the
routes as required for the project. At the very least you would have a
project-specific end point which would subclass the `ApiController` for example,
`MyProjectsApi`.

_app/\_config/routes.yml_

```yml
SilverStripe\Control\Director:
  rules:
    'api/v1/auth/$Action': 'FullscreenInteractive\Restful\Controllers\AuthController'
    'api/v1/projects//$Action': 'MyProjectsApi'
```

Here is an example of `MyProjectsApi` which demostrates some of the helpers
provided by this module. Anyone can `GET api/v1/projects/` to retrieve a
list of all projects, logged in ADMIN users can `POST api/v1/projects/create`

_app/src/Project.php_

```php
<?php

use FullscreenInteractive\Restful\Interfaces\ApiReadable;
use SilverStripe\Security\Member;
use SilverStripe\ORM\DataObject;

class Project extends DataObject implements ApiReadable
{
    private static $db = [
        'Title' => 'Varchar(100)',
        'Date' => 'DBDate'
    ];

    private static $has_one = [
        'Author' => Member::class
    ];

    public function toApi(): array
    {
        return [
            'title' => $this->Title,
            'date' => $this->dbObject('Date')->getTimestamp()
        ];
    }
}
```

_app/src/MyProjectsApi.php_

```php
<?php

class MyProjectsApi extends FullscreenInteractive\Restful\Controllers\ApiController
{
    private static $allowed_actions = [
        'index',
        'createProject',
        'deleteProject'
    ];

    public function index()
    {
        $this->ensureGET();

        return $this->returnPaginated(Project::get());
    }

    public function createProject()
    {
        $this->ensurePOST();

        $member = $this->ensureUserLoggedIn([
            'ADMIN'
        ]);

        list($title, $date) = $this->ensureVars([
            'Title',
            'Date' => function($value) {
                return strtotime($value) > 0
            }
        ]);

        $project = new Project();
        $project->Title = $title;
        $project->Date = $date;
        $project->AuthorID = $member->ID;
        $project->write();

        return $this->returnJSON([
            'project' => $project->toApi()
        ]);
    }

    public function deleteProject()
    {
        $this->ensurePOST();

        $member = $this->ensureUserLoggedIn([
            'ADMIN'
        ]);

        list($id) = $this->ensureVars([
            'id'
        ]);

        $project = Project::get()->byID($id);

        if (!$project) {
            return $this->failure([
                'status_code' => 404,
                'message' => 'Unknown project'
            ]);
        }

        if ($project->canDelete($member)) {
            $project->delete();
        }

        return $this->success();
    }
}
```

## Authenication

Authenication is managed via a `JWT` which can be stored client side. To
receive a token the user must first exchange their username / password over
basic authenication by making a `POST` request with the credentials. Usually
this is some form of javascript request e.g

```js
fetch('/api/v1/auth/token', {
    method: "POST",
    headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cache-control": "no-cache",
        "Authorization": "Basic " + base64.encode(email + ":" + password),
    },
})
```

The response from that request with either be an error code (> 200) or if user
and password is correct, a 200 response containing the JWT. The token and
related meta data can be saved securely client side for reuse.

```js
{
    "token": "eyJ0eXAiOiJKV1QiL...",
    "member": {
        "id": 1,
        "email": "js@lvl51.de",
        "firstName": "Julian",
        "surname": "Scheuchenzuber"
    }
}
```

If a user's token is invalid, or expired a *401* error will be returned. To
validate a users token use the `verify` endpoint - this will check the token and
renew the token if required.

```js
fetch('/api/v1/auth/verify', {
    method: "GET",
    headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
    Authorization: "Bearer " + token,
    },
})
```

The token can then be used to sign API calls as the `Bearer` header.

```js
fetch('/api/v1/projects/createProject', {
    method: "POST",
    headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cache-control": "no-cache",
        Authorization: "Bearer " + token,
    },
})
```

## Authenication via silverstripe-apikeys

If you would prefer to use API keys rather than JWT tokens, you can use 
https://github.com/sminnee/silverstripe-apikey and configure it as a route
specific middleware 

```yml
SilverStripe\Core\Injector\Injector:
  ApiRouteMiddleware:
    class: SilverStripe\Control\Middleware\RequestHandlerMiddlewareAdapter
    properties:
      RequestHandler: '%$MyProjectApi'
      Middlewares:
        CustomMiddleware: '%$ApiKeyRequestMiddleware'
  MyProjectApi:
    class: MyProjectApi
  ApiKeyRequestMiddleware:
    class: Sminnee\ApiKey\ApiKeyRequestMiddleware
SilverStripe\Control\Director:
  rules:
    api:
      Controller: '%$ApiRouteMiddleware'

```

Out of the box, the silverstripe-apikey module will not throw an error if
no API key is provided (but it will if a wrong one is). So in the short term
you're best to double check and handle if the API key is not provided

```
public function projects()
{
  if (!$this->ensureUserLoggedIn()) {
    return $this->failure(401);
  }
  
  // ..
}
```


## UUIDs

https://stackoverflow.com/questions/56576985/is-it-a-bad-practice-to-expose-the-database-id-to-the-client-in-your-rest-api/56577271

When designing an API you may wish to avoid exposing your internal ID's to
in responses.

To add a UUID field to your object add the following extension to your model

```php
private static $extensions = [
    UuidableExtension::class
];
```

A UUID will be generated on an objects `onBeforeWrite()` .

## FAQ

### I'm getting a 301 redirect when trying to call my api/endpoint

In Silverstripe 5 `CanonicalURLMiddleware` is enabled to add a trialing 
slash by default. This can cause issues in production so we recommend
disabling this completely for any API routes.

```yml
SilverStripe\Core\Injector\Injector:
  SilverStripe\Control\Middleware\CanonicalURLMiddleware:
    properties:
      enforceTrailingSlashConfigIgnorePaths:
        - 'api/'
```

## API Documentation

Todo but it's not massive. See `ApiController` for now.

## Licence

BSD-3-Clause
