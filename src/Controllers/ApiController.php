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

        // normalize query variables
        if (strpos($this->request->getHeader('Content-Type'), 'application/json') !== false) {
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
    protected function success(array $context = []): HTTPResponse
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
    protected function failure(array $context = [])
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
     *
     * @return array
     */
    public function prepPaginatedOutput(SS_List $list, $keyFunc = null, $dataFunc = null): array
    {
        $list = new PaginatedList($list, $this->request);
        $list->setPageLength(100);
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

        if (isset($_SERVER['Authorization'])) {
            $header = trim($_SERVER["Authorization"]);
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $header = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));

            if (isset($requestHeaders['Authorization'])) {
                $header = trim($requestHeaders['Authorization']);
            }
        }

        return $header;
    }

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

        $err = new HTTPResponse_Exception();
        $err->setResponse($response);

        throw $err;
    }

    /**
     * @param string
     *
     * @return mixed
     */
    protected function getVar($name)
    {
        $key = strtolower($name);

        return (isset($this->vars[$key])) ? $this->vars[$key] : null;
    }

    /**
     * @param string
     *
     * @return boolean
     */
    protected function hasVar($name)
    {
        $key = strtolower($name);

        return (isset($this->vars[$key]));
    }

    /**
     * @param array
     *
     * @return boolean
     * @throws HTTPResponse_Exception
     */
    protected function ensureVars(array $vars = [])
    {
        foreach ($vars as $k => $v) {
            if ($v && is_callable($v)) {
                if (!$this->hasVar($k) || !$v($this->getVar($k))) {
                    throw $this->httpError(400, 'Missing required variable: '. $v);
                }
            } elseif (!$this->hasVar($v)) {
                throw $this->httpError(400, 'Missing required variable: '. $v);
            }
        }

        return true;
    }

    /**
     * @param mixed
     *
     * @return HTTPResponse
     */
    protected function returnJSON($arr)
    {
        return $this->getResponse()->setBody(json_encode($arr));
    }

    /**
     * @throws HTTPResponse_Exception
     */
    protected function ensureGET()
    {
        if (!$this->request->isGet()) {
            $this->httpError(400, 'Request must be provided as a GET request');
        }
    }

    /**
     * @throws HTTPResponse_Exception
     */
    protected function ensurePOST()
    {
        if (!$this->request->isPost()) {
            $this->httpError(400, 'Request must be provided as a POST request');
        }
    }
}
