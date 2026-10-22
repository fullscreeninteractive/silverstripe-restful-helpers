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

If you plan on using authentication for your API then you first need to
configure a secret for signing JWTs. The secret must be at least 32 bytes and
should be loaded from the environment rather than committed to your repository.

_.env_

```
JWT_SECRET="generate-with: openssl rand -base64 48"
```

_app/\_config/api.yml_

```yml
FullscreenInteractive\Restful\Auth\JWTUtils:
  secret: '`JWT_SECRET`'
  # How long a token is valid for without being renewed
  lifetime_in_days: 7
  # How often a token is reissued with a fresh expiry
  renew_threshold_in_minutes: 60
  # Optional hard limit after which the user must log in again (null = none)
  max_lifetime_in_days: 30

FullscreenInteractive\Restful\Controllers\ApiController:
  # Origins allowed to call the API from a browser. Defaults to ['*'].
  allowed_origins:
    - 'https://app.example.com'
```

### Upgrading from 1.x

Earlier versions depended on `level51/silverstripe-jwt-utils`. That code is now
part of this module, so rename any `Level51\JWTUtils\JWTUtils` config or code
references to `FullscreenInteractive\Restful\Auth\JWTUtils`. Existing tokens
remain valid as long as the secret is unchanged and at least 32 bytes long;
shorter secrets are rejected and must be rotated (which logs out all users).

Other behaviour changes:

- A valid bearer token sets the current user for that request only and no
  longer creates a session (cookie) login.
- Tokens for deleted or locked out members are rejected with a `401`.
- `ensureUserLoggedIn($permissions)` returns `403` rather than `401` when the
  member is authenticated but lacks the permission.

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
        "email": "jane@example.com",
        "firstName": "Jane",
        "surname": "Doe"
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

The token can then be used to sign API calls as the `Bearer` header. If the
token was renewed, use the new token from the `verify` response for later
requests.

Note that the `token` endpoint authenticates with email and password only, so
it does not enforce multi-factor authentication. Only expose it over HTTPS.

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
