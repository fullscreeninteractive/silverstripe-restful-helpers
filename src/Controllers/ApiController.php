<?php

declare(strict_types=1);

namespace FullscreenInteractive\Restful\Controllers;

use ArrayAccess;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Level51\JWTUtils\JWTUtils;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Model\List\PaginatedList;
use SilverStripe\Model\List\SS_List;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

class ApiController extends Controller
{
    public function init()
    {
        parent::init();

        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
            $response = $this->getResponse()
                ->addHeader('Access-Control-Allow-Origin', '*')
                ->addHeader("Content-type", "application/json");

            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
                $response = $response->addHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            }

            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
                $response = $response->addHeader(
                    'Access-Control-Allow-Headers',
                    $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']
                );
            }

            $response->output();
            exit;
        }

        $contentType = (string) $this->request->getHeader('Content-Type');

        if (strpos($contentType, 'application/json') !== false) {
            $jsonPayload = trim(file_get_contents("php://input"));
            $input = json_decode($jsonPayload, true);

            if ($input) {
                $this->vars = array_merge($input, $this->request->getVars());
            } elseif ($jsonPayload) {
                $error = json_last_error();

                switch ($error) {
                    case JSON_ERROR_NONE:
                        $this->vars = $this->request->getVars();
                        break;
                    default:
                        $this->failure([
                            'error' => 'Invalid JSON',
                            'code' => $error
                        ]);
                        break;
                }
            } else {
                $this->vars = $this->request->requestVars();
            }
        } else {
            $this->vars = $this->request->requestVars();
        }

        if ($this->vars) {
            $this->vars = array_change_key_case($this->vars);
        }

        $this->getResponse()
            ->addHeader('Access-Control-Allow-Origin', '*')
            ->addHeader("Content-type", "application/json");
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
    ): array
    {
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
        $token = JWT::decode(
            $this->getJwt(),
            new Key(
                Config::inst()->get(JWTUtils::class, 'secret'),
                'HS256'
            )
        );

        $member = Member::get()->byID($token->memberId);

        if ($member) {
            if ($permissionCodes) {
                if (!Permission::checkMember($member, $permissionCodes)) {
                    return $this->httpError(401);
                }
            }

            Injector::inst()->get(IdentityStore::class)->logIn($member);

            Security::setCurrentUser($member);

            return $member;
        } else {
            return $this->httpError(401);
        }
    }

    /**
     * Returns the JWT token from the Authorization header.
     *
     * @throws HTTPResponse_Exception
     */
    public function getJwt(): string
    {
        $bearer = $this->getBearerToken();

        if (!$bearer) {
            return $this->httpError(401);
        }

        if (!JWTUtils::inst()->check($bearer)) {
            return $this->httpError(401);
        }

        $token = JWT::decode(
            $bearer,
            new Key(
                Config::inst()->get(JWTUtils::class, 'secret'),
                'HS256'
            )
        );

        $jwt = JWTUtils::inst()->renew($bearer);

        if (!$jwt) {
            return $this->httpError(401);
        }

        // Set the current user
        $memberId = $token->memberId;
        $member = Member::get()->byID($memberId);

        if ($member) {
            Injector::inst()->get(IdentityStore::class)->logIn($member);
            Security::setCurrentUser($member);
        }

        return $jwt;
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
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
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
        $response->addHeader('Access-Control-Allow-Origin', '*');

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
