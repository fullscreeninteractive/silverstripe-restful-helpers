<?php

namespace FullscreenInteractive\Restful\Controllers;

use Firebase\JWT\JWT;
use Level51\JWTUtils\JWTUtils;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\PaginatedList;
use SilverStripe\ORM\SS_List;
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
            $input = json_decode(file_get_contents("php://input"), true);

            if ($input) {
                $this->vars = array_merge($input, $this->request->getVars());
            } else {
                $this->vars = $this->request->getVars();
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
     *
     * @param array $context
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
     *
     * @param array $context
     */
    public function failure(array $context = [])
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

    /**
     * @param SS_List $list
     * @param callable $keyFunc
     * @param callable $dataFunc
     *
     * @return HTTPResponse
     */
    public function returnPaginated(SS_List $list, $keyFunc = null, $dataFunc = null)
    {
        list($list, $output) = $this->prepPaginatedOutput($list, $keyFunc, $dataFunc);

        return $this->returnArray([
            'records' => $output,
            'start' => $list->getPageStart(),
            'limit' => $list->getPageLength(),
            'total' => $list->getTotalItems(),
            'more' => ($list->NextLink()) ? true : false
        ]);
    }

    /**
     * @param array
     *
     * @return HTTPResponse
     */
    public function returnArray($arr)
    {
        return $this->getResponse()->setBody(json_encode($arr));
    }


    /**
     * Convert a provided DataList to a PaginatedList and return the source.
     *
     * @param SS_List $list
     * @param callable $keyFunc
     * @param callabale $dataFunc
     * @param int $pageLength
     *
     * @return array
     */
    public function prepList(SS_List $list, $keyFunc = null, $dataFunc = null): array
    {
        $output = [];

        foreach ($list as $item) {
            if ($dataFunc) {
                $record = $dataFunc($item);
            } else if (is_array($item)) {
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
     *
     * @param SS_List $list
     * @param callable $keyFunc
     * @param callabale $dataFunc
     * @param int $pageLength
     *
     * @return array
     */
    public function prepPaginatedOutput(SS_List $list, $keyFunc = null, $dataFunc = null, $pageLength = 100): array
    {
        $list = new PaginatedList($list, $this->request);
        $list->setPageLength($pageLength);
        $output = [];

        foreach ($list as $item) {
            if ($dataFunc) {
                $record = $dataFunc($item);
            } else if (is_array($item)) {
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
     * @param array $permissionCodes
     *
     * @return Member
     * @throws HTTPResponse_Exception
     */
    public function ensureUserLoggedIn($permissionCodes = [])
    {
        $token = JWT::decode(
            $this->getJwt(),
            Config::inst()->get(JWTUtils::class, 'secret'),
            ['HS256']);

        $member = Member::get()->byID($token->memberId);

        if ($member) {
            if ($permissionCodes) {
                if (!Permission::checkMember($member, $permissionCodes)) {
                    return $this->httpError(401);
                }
            }

            $member->login();

            Security::setCurrentUser($member);

            return $member;
        } else {
            return $this->httpError(401);
        }
    }

    /**
     * @return string The renewed decoded token
     */
    public function getJwt()
    {
        $bearer = $this->getBearerToken();

        if (!$bearer) {
            return $this->httpError(401);
        }

        if (!JWTUtils::inst()->check($bearer)) {
            return $this->httpError(401);
        }

        $jwt = JWTUtils::inst()->renew($bearer);

        if (!$jwt) {
            return $this->httpError(401);
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
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));

            if (isset($requestHeaders['Authorization'])) {
                $header = trim($requestHeaders['Authorization']);
            }
        }

        return $header;
    }

    /**
     * Returns the bearer token value from the Authorization Header
     *
     * @return string
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

        $response = new HTTPResponse(
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
     * @param string
     *
     * @return mixed
     */
    public function getVar($name)
    {
        $key = strtolower($name);

        return (isset($this->vars[$key])) ? $this->vars[$key] : null;
    }

    /**
     * @param string
     *
     * @return boolean
     */
    public function hasVar($name)
    {
        $key = strtolower($name);

        return (isset($this->vars[$key]));
    }

    /**
     * Returns an array of all the variables listed from the POST or GET vars
     *
     *
     * @param array
     *
     * @return array
     *
     * @throws HTTPResponse_Exception
     */
    public function ensureVars(array $vars = [])
    {
        $output = [];

        foreach ($vars as $k => $v) {
            if ($v && is_callable($v)) {
                if (!$this->hasVar($k) || !$v($this->getVar($k))) {
                    throw $this->httpError(400, 'Missing required variable: '. $v);
                }

                $output[] = $this->getVar($k);
            } elseif (!$this->hasVar($v)) {
                throw $this->httpError(400, 'Missing required variable: '. $v);
            } else {
                $output[] = $this->getVar($v);
            }
        }

        return $output;
    }

    /**
     * @param mixed
     *
     * @return HTTPResponse
     */
    public function returnJSON($arr)
    {
        return $this->getResponse()->setBody(json_encode($arr));
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
