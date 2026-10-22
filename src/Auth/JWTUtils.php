<?php

namespace FullscreenInteractive\Restful\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\BasicAuth;
use SilverStripe\Security\Member;
use Throwable;

/**
 * Issues, validates and renews the HS256 signed JWTs used by the API.
 *
 * ```yml
 * FullscreenInteractive\Restful\Auth\JWTUtils:
 *   secret: '`JWT_SECRET`'
 * ```
 */
class JWTUtils
{
    use Configurable;

    public const ALGORITHM = 'HS256';

    /**
     * HS256 requires a key of at least 256 bits.
     */
    public const MIN_SECRET_LENGTH = 32;

    /**
     * Config key used by the level51/silverstripe-jwt-utils module this class
     * replaces. Only used to give a helpful error when a project still has it.
     */
    private const LEGACY_CLASS = 'Level51\\JWTUtils\\JWTUtils';

    /**
     * Signing secret. Supports the `ENV_VAR` backtick syntax.
     *
     * @config
     * @var string|null
     */
    private static $secret = null;

    /**
     * Issuer written to, and required in, every token. Defaults to the site's
     * absolute base URL. Set this explicitly if the API is served from more
     * than one domain, otherwise tokens only work on the domain issuing them.
     *
     * @config
     * @var string|null
     */
    private static $iss = null;

    /**
     * @config
     * @var int
     */
    private static $lifetime_in_days = 7;

    /**
     * @config
     * @var int
     */
    private static $renew_threshold_in_minutes = 60;

    /**
     * Hard limit, measured from the original login (iat), after which a token
     * can no longer be renewed and the user must log in again. Null disables
     * the limit.
     *
     * @config
     * @var int|null
     */
    private static $max_lifetime_in_days = null;

    /**
     * @internal
     * @var JWTUtils|null
     */
    private static $instance = null;

    private string $signingKey;

    /**
     * @throws JWTUtilsException
     */
    public static function inst(): JWTUtils
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function tearDown(): void
    {
        self::$instance = null;
    }

    /**
     * @throws JWTUtilsException
     */
    private function __construct()
    {
        $secret = Injector::inst()->convertServiceProperty(static::config()->get('secret'));

        if (!is_string($secret) || $secret === '') {
            if (self::hasLegacyConfig()) {
                throw new JWTUtilsException(sprintf(
                    'JWT config must now be set on %s instead of %s.',
                    self::class,
                    self::LEGACY_CLASS
                ));
            }

            throw new JWTUtilsException('No "secret" config found.');
        }

        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new JWTUtilsException(sprintf(
                'The JWT "secret" must be at least %d bytes long.',
                self::MIN_SECRET_LENGTH
            ));
        }

        $this->signingKey = $secret;
    }

    private function __clone()
    {
    }

    private static function hasLegacyConfig(): bool
    {
        try {
            return (bool) Config::inst()->get(self::LEGACY_CLASS, 'secret');
        } catch (Throwable $e) {
            return false;
        }
    }

    private function calcExpirationClaim(?int $issuedAt = null): int
    {
        $days = (int) static::config()->get('lifetime_in_days');
        $exp = time() + ($days * 24 * 60 * 60);

        $maxDays = static::config()->get('max_lifetime_in_days');

        if ($maxDays && $issuedAt) {
            $exp = min($exp, $issuedAt + ((int) $maxDays * 24 * 60 * 60));
        }

        return $exp;
    }

    public function getIssuer(): string
    {
        return (string) (static::config()->get('iss') ?: Director::absoluteBaseURL());
    }

    public function getClaims(): array
    {
        return [
            'iss' => $this->getIssuer(),
            'exp' => $this->calcExpirationClaim(),
            'iat' => time(),
            'rat' => time(),
            'jti' => bin2hex(random_bytes(16))
        ];
    }

    public function encode(array $payload): string
    {
        return JWT::encode($payload, $this->signingKey, self::ALGORITHM);
    }

    /**
     * Verifies the signature, expiry and issuer of the token and that it
     * identifies a member. Returns the claims.
     *
     * This does not check the member still exists or that the token has not
     * been revoked, see {@link isValidForMember()}.
     *
     * @throws JWTUtilsException
     */
    public function decode(string $token): array
    {
        try {
            $claims = (array) JWT::decode($token, new Key($this->signingKey, self::ALGORITHM));
        } catch (\Exception $e) {
            throw new JWTUtilsException($e->getMessage(), 0, $e);
        }

        if (!isset($claims['iss']) || $claims['iss'] !== $this->getIssuer()) {
            throw new JWTUtilsException('Token was not issued by this site');
        }

        $memberId = filter_var($claims['memberId'] ?? null, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1]
        ]);

        if ($memberId === false) {
            throw new JWTUtilsException('Token does not identify a member');
        }

        $claims['memberId'] = $memberId;

        $maxDays = static::config()->get('max_lifetime_in_days');

        if ($maxDays) {
            $issuedAt = isset($claims['iat']) ? (int) $claims['iat'] : 0;

            if ($issuedAt + ((int) $maxDays * 24 * 60 * 60) < time()) {
                throw new JWTUtilsException('Token has exceeded its maximum lifetime');
            }
        }

        return $claims;
    }

    public function createTokenForMember(Member $member): string
    {
        return $this->encode(array_merge([
            'memberId' => (int) $member->ID,
            'ver' => self::getTokenVersion($member)
        ], $this->getClaims()));
    }

    /**
     * Checks decoded claims belong to the member and have not been revoked.
     */
    public function isValidForMember(array $claims, Member $member): bool
    {
        return isset($claims['memberId'])
            && (int) $claims['memberId'] === (int) $member->ID
            && (int) ($claims['ver'] ?? 0) === self::getTokenVersion($member);
    }

    /**
     * Invalidates every token previously issued to the member. This happens
     * automatically when the member's password changes.
     */
    public static function revokeTokensForMember(Member $member): void
    {
        $member->JWTTokenVersion = self::getTokenVersion($member) + 1;
        $member->write();
    }

    private static function getTokenVersion(Member $member): int
    {
        return (int) $member->JWTTokenVersion;
    }

    /**
     * @throws JWTUtilsException
     */
    public function byBasicAuth(HTTPRequest $request, bool $includeMemberData = true): array
    {
        try {
            $member = BasicAuth::requireLogin($request, 'API', null, false);
        } catch (HTTPResponse_Exception $e) {
            throw new JWTUtilsException((string) $e->getResponse()->getBody());
        }

        // requireLogin() returns true rather than a member when running on the
        // CLI or when the database is not ready. Never issue a token for that.
        if (!$member instanceof Member || !$member->isInDB()) {
            throw new JWTUtilsException('Invalid credentials');
        }

        $payload = [
            'token' => $this->createTokenForMember($member)
        ];

        if ($includeMemberData) {
            $payload['member'] = [
                'id' => $member->ID,
                'email' => $member->Email,
                'firstName' => $member->FirstName,
                'surname' => $member->Surname
            ];
        }

        return $payload;
    }

    /**
     * Returns the token unchanged if it was renewed recently, otherwise a new
     * token with an extended expiry.
     *
     * @throws JWTUtilsException
     */
    public function renew(string $token): string
    {
        $jwt = $this->decode($token);

        $renewedAt = isset($jwt['rat']) ? (int) $jwt['rat'] : 0;
        $renewAgeMinutes = (time() - $renewedAt) / 60;

        if ($renewAgeMinutes < (int) static::config()->get('renew_threshold_in_minutes')) {
            return $token;
        }

        $jwt['exp'] = $this->calcExpirationClaim(isset($jwt['iat']) ? (int) $jwt['iat'] : null);
        $jwt['rat'] = time();

        return $this->encode($jwt);
    }

    public function check(string $token): bool
    {
        try {
            $this->decode($token);

            return true;
        } catch (JWTUtilsException $e) {
            return false;
        }
    }
}
