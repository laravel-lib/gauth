<?php

namespace LaravelLib\GAuth\Facades;

use LaravelLib\GAuth\GoogleAuthenticator;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string generateSecret()
 * @method static bool checkCode($secret, $code, $discrepancy = 1)
 * @method static string generateQrUrl(string $accountName, string $secret, ?string $issuer = null, int $size = 200)
 */

class GAuth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return GoogleAuthenticator::class;
    }
}
