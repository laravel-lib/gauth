<?php

namespace LaravelLib\GAuth\Contracts;

interface GoogleAuthenticatorInterface
{
    public function generateSecret(): string;
    public function checkCode($secret, $code, $discrepancy = 1): bool;
    public function getCode($secret, $time = null): string;
    public function generateQrUrl(string $accountName, string $secret, ?string $issuer = null, int $size = 200): string;
}
