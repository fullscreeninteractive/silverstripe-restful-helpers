<?php

declare(strict_types=1);

namespace FullscreenInteractive\Restful\Controllers;

use ArrayAccess;
use FullscreenInteractive\Restful\Auth\JWTUtils;
use FullscreenInteractive\Restful\Auth\JWTUtilsException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Model\List\PaginatedList;
use SilverStripe\Model\List\SS_List;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

class ApiController extends Controller
{
    /**
     * Origins allowed to make cross-origin requests. Include '*' to allow any
     * origin. Authentication is by bearer token only, never cookies.
     *
     * @config
     * @var string[]
     */
    private static $allowed_origins = ['*'];

    /**
     * @var array
     */
    protected $vars = [];

    private ?Member $jwtMember = null;

    private ?string $renewedJwt = null;

    public function init()
    {
        parent::init();

        if ($this->request->httpMethod() === 'OPTIONS') {
            $response = $this->addCorsHeaders($this->getResponse())
                ->addHeader("Content-type", "application/json");

            if ($this->request->getHeader('Access-Control-Request-Method')) {
                $response = $response->addHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            }

            if ($requestHeaders = $this->request->getHeader('Access-Control-Request-Headers')) {
                $response = $response->addHeader(
                    'Access-Control-Allow-Headers',
                    preg_replace('/[^A-Za-z0-9\-_, ]/', '', $requestHeaders)
                );
            }

            $response->output();
            exit;
        }

        $this->addCorsHeaders($this->getResponse())
            ->addHeader("Content-type", "application/json")
            ->addHeader('X-Content-Type-Options', 'nosniff');

        $contentType = (string) $this->request->getHeader('Content-Type');
        $jsonPayload = trim((string) $this->request->getBody());

        if (strpos($contentType, 'application/json') !== false && $jsonPayload !== '') {
            $input = json_decode($jsonPayload, true);
            $error = json_last_error();

            if ($error !== JSON_ERROR_NONE) {
                // An error status marks the response finished so no action runs
                $this->failure([
                    'error' => 'Invalid JSON',
                    'code' => $error
                ]);

                return;
            }

            $this->vars = is_array($input)
                ? array_merge($input, $this->request->getVars())
                : $this->request->getVars();
        } else {
            $this->vars = $this->request->requestVars();
        }

        if ($this->vars) {
            $this->vars = array_change_key_case($this->vars);
        }
    }

    /**
     * Adds the Access-Control-Allow-Origin header for allowed origins.
     */
    protected function addCorsHeaders(HTTPResponse $response): HTTPResponse
    {
        $allowed = (array) static::config()->get('allowed_origins');

        if (in_array('*', $allowed, true)) {
            return $response->addHeader('Access-Control-Allow-Origin', '*');
        }

        $origin = $this->getRequest()->getHeader('Origin');

        if ($origin && in_array($origin, $allowed, true)) {
            $response->addHeader('Access-Control-Allow-Origin', $origin);
        }

        return $response->addHeader('Vary', 'Origin');
    }


    public function index()
    {
        return $this->httpError(400, 'Bad Request');
    }

    /**
     * Outputs a successful response (200)
     */
    public function success(array $context = []): HTTPResponse
    {
        $this->getResponse()->setBody(json_encode(array_merge([
            'timestamp' => time(),
            'success' => 1
        ], $context)));

        return $this->getResponse();
    }

    /**
     * Returns a error response.
     */
    public function failure(array $context = []): HTTPResponse
    {
        $response = $this->getResponse();

        $response->setBody(json_encode(array_merge([
            'timestamp' => time(),
            'success' => 0
        ], $context)));

        if (isset($context['status_code'])) {
            $response->setStatusCode($context['status_code']);
        } else {
            $response->setStatusCode(400);
        }

        return $response;
    }

    public function returnPaginated(
        ArrayAccess $list,
        ?callable $keyFunc = null,
        ?callable $dataFunc = null,
        ?int $pageLength = 100
    ): HTTPResponse {
        list($list, $output) = $this->prepPaginatedOutput($list, $keyFunc, $dataFunc, $pageLength);

        return $this->returnArray([
            'records' => $output,
            'start' => $list->getPageStart(),
            'limit' => $list->getPageLength(),
            'total' => $list->getTotalItems(),
            'more' => ($list->NextLink()) ? true : false
        ]);
    }


    /**
     * Returns a HTTP response with the provided data encoded as JSON.
     */
    public function returnArray(array $data): HTTPResponse
    {
        return $this->getResponse()->setBody(json_encode($data));
    }


    /**
     * Convert a provided DataList to a PaginatedList and return the source.
     */
    public function prepList(SS_List $list, ?callable $keyFunc = null, ?callable $dataFunc = null): array
    {
        $output = [];

        foreach ($list as $item) {
            if ($dataFunc) {
                $record = $dataFunc($item);
            } elseif (is_array($item)) {
                $record = $item;
            } else {
                $record = $item->toApi();
            }

            if ($keyFunc) {
                $output[$keyFunc($item)] = $record;
            } else {
                $output[] = $record;
            }
        }

        return [
            $list,
            $output
        ];
    }


    /**
     * Convert a provided List to a PaginatedList and return the source.
     */
    public function prepPaginatedOutput(
        SS_List $list,
        ?callable $keyFunc = null,
        ?callable $dataFunc = null,
        ?int $pageLength = null
    ): array {
        $list = PaginatedList::create($list, $this->request);

        if ($pageLength) {
            $list->setPageLength($pageLength);
        }

        $output = [];

        foreach ($list as $item) {
            if ($dataFunc) {
                $record = $dataFunc($item);
            } elseif (is_array($item)) {
                $record = $item;
            } else {
                $record = $item->toApi();
            }

            if ($keyFunc) {
                $output[$keyFunc($item)] = $record;
            } else {
                $output[] = $record;
            }
        }

        return [
            $list,
            $output
        ];
    }

    /**
     * If this endpoint requires authorization then we want to get the member
     * for the operation.
     *
     * @throws HTTPResponse_Exception
     */
    public function ensureUserLoggedIn(?array $permissionCodes = null): Member
    {
        $member = $this->authenticateJwt();

        if ($permissionCodes && !Permission::checkMember($member, $permissionCodes)) {
            return $this->httpError(403);
        }

        return $member;
    }

    /**
     * Validates the bearer token and returns it, renewed if required.
     *
     * @throws HTTPResponse_Exception
     */
    public function getJwt(): string
    {
        $this->authenticateJwt();

        return $this->renewedJwt;
    }

    /**
     * Validates the bearer token and sets the member it identifies as the
     * current user for this request only. The member is deliberately not
     * persisted to the session so that a token never creates a cookie login.
     *
     * @throws HTTPResponse_Exception
     */
    protected function authenticateJwt(): Member
    {
        if ($this->jwtMember) {
            return $this->jwtMember;
        }

        $bearer = $this->getBearerToken();

        if (!$bearer) {
            return $this->httpError(401);
        }

        // Configuration errors should surface rather than look like a 401
        $utils = JWTUtils::inst();

        try {
            $claims = $utils->decode($bearer);
            $renewed = $utils->renew($bearer);
        } catch (JWTUtilsException $e) {
            return $this->httpError(401);
        }

        $member = Member::get()->byID($claims['memberId']);

        if (!$member || !$member->canLogin()) {
            return $this->httpError(401);
        }

        Security::setCurrentUser($member);

        $this->jwtMember = $member;
        $this->renewedJwt = $renewed;

        return $member;
    }

    public function getAuthorizationHeader(): string
    {
        $header = '';

        if ($auth = $this->getRequest()->getHeader('Authorization')) {
            $header = trim($auth);
        } elseif ($auth = $this->getRequest()->getHeader('HTTP_AUTHORIZATION')) {
            $header = trim($auth);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(
                array_map('ucwords', array_keys($requestHeaders)),
                array_values($requestHeaders)
            );

            if (isset($requestHeaders['Authorization'])) {
                $header = trim($requestHeaders['Authorization']);
            }
        }

        return $header;
    }

    /**
     * Returns the bearer token value from the Authorization Header
     */
    public function getBearerToken(): string
    {
        $headers = $this->getAuthorizationHeader();

        if (!empty($headers)) {
            if (preg_match('/^Bearer\s+(\S+)$/i', $headers, $matches)) {
                return $matches[1];
            }
        }

        return '';
    }

    /**
     * @param int $errorCode
     * @param string $errorMessage
     *
     * @throws HTTPResponse_Exception
     */
    public function httpError($errorCode = 404, $errorMessage = '')
    {
        if (!$errorMessage) {
            switch ($errorCode) {
                case 404:
                    $errorMessage = 'Missing resource';
                    break;
                case 400:
                    $errorMessage = 'Bad Request';
                    break;
                default:
                    $errorMessage = 'Permission denied resource';
                    break;
            }
        }

        $body = json_encode([
            'error' => $errorMessage,
            'code' => $errorCode
        ]);

        $response = HTTPResponse::create(
            $body,
            $errorCode
        );

        $response->addHeader("Content-type", "application/json");
        $response->addHeader('X-Content-Type-Options', 'nosniff');
        $this->addCorsHeaders($response);

        $err = new HTTPResponse_Exception();
        $err->setResponse($response);

        throw $err;
    }

    /**
     * Returns a variable from the POST or GET vars
     */
    public function getVar(string $name): mixed
    {
        $key = strtolower($name);

        return (isset($this->vars[$key])) ? $this->vars[$key] : null;
    }

    /**
     * Checks if a variable exists in the POST or GET vars
     */
    public function hasVar(string $name): bool
    {
        $key = strtolower($name);

        return (isset($this->vars[$key]));
    }

    /**
     * Returns an array of all the variables listed from the POST or GET vars
     *
     * @throws HTTPResponse_Exception
     */
    public function ensureVars(?array $vars = [])
    {
        $output = [];

        foreach ($vars as $k => $v) {
            if ($v && is_callable($v)) {
                if (!$this->hasVar($k) || !$v($this->getVar($k))) {
                    throw $this->httpError(400, 'Missing required variable: ' . $k);
                }

                $output[] = $this->getVar($k);
            } elseif (!$this->hasVar($v)) {
                throw $this->httpError(400, 'Missing required variable: ' . $v);
            } else {
                $output[] = $this->getVar($v);
            }
        }

        return $output;
    }


    public function returnJSON(mixed $value): HTTPResponse
    {
        return $this->getResponse()->setBody(json_encode($value));
    }

    /**
     * @throws HTTPResponse_Exception
     */
    public function ensureGET()
    {
        if (!$this->request->isGet()) {
            $this->httpError(400, 'Request must be provided as a GET request');
        }
    }

    /**
     * @throws HTTPResponse_Exception
     */
    public function ensurePOST()
    {
        if (!$this->request->isPost()) {
            $this->httpError(400, 'Request must be provided as a POST request');
        }
    }

    /**
     * @throws HTTPResponse_Exception
     */
    public function ensureDelete(): void
    {
        if ($this->request->isDELETE()) {
            return;
        }

        $this->httpError(400, 'Request must be provided as a DELETE request');
    }
}
