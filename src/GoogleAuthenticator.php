<?php

namespace LaravelLib\GAuth;

use LaravelLib\GAuth\Exceptions\RuntimeException;
use LaravelLib\GAuth\Contracts\GoogleAuthenticatorInterface;

final class GoogleAuthenticator implements GoogleAuthenticatorInterface
{
    private $passCodeLength;
    private $secretLength;
    private $pinModulo;
    private $instanceTime;
    private $codePeriod;
    private $periodSize = 30;

    public function __construct(int $passCodeLength = 6, int $secretLength = 10, ?\DateTimeInterface $instanceTime = null, int $codePeriod = 30)
    {
        $this->passCodeLength = $passCodeLength;
        $this->secretLength = $secretLength;
        $this->codePeriod = $codePeriod;
        $this->periodSize = $codePeriod < $this->periodSize ? $codePeriod : $this->periodSize;
        $this->pinModulo = 10 ** $passCodeLength;
        $this->instanceTime = $instanceTime ?? new \DateTimeImmutable();
    }

    public function generateSecret(): string
    {
        return (new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true))
            ->encode(random_bytes($this->secretLength));
    }

    /**
     * @param string $secret
     * @param string $code
     * @param int    $discrepancy
     */
    public function checkCode($secret, $code, $discrepancy = 1): bool
    {
        $periods = floor($this->codePeriod / $this->periodSize);

        $result = 0;
        for ($i = -$discrepancy; $i < $periods + $discrepancy; ++$i) {
            $dateTime = new \DateTimeImmutable('@' . ($this->instanceTime->getTimestamp() - ($i * $this->periodSize)));
            $result = hash_equals($this->getCode($secret, $dateTime), $code) ? $dateTime->getTimestamp() : $result;
        }

        return $result > 0;
    }

    /**
     * @param string      $accountName The account name to show and identify
     * @param string      $secret      The secret is the generated secret unique to that user
     * @param string|null $issuer      Where you log in to
     * @param int         $size        Image size in pixels, 200 will make it 200x200
     */
    public function generateQrUrl(string $accountName, string $secret, ?string $issuer = null, int $size = 200): string
    {
        if ('' === $accountName || false !== strpos($accountName, ':')) {
            throw RuntimeException::InvalidAccountName($accountName);
        }

        if ('' === $secret) {
            throw RuntimeException::InvalidSecret();
        }

        $label = $accountName;
        $otpauthString = 'otpauth://totp/%s?secret=%s';

        if (null !== $issuer) {
            if ('' === $issuer || false !== strpos($issuer, ':')) {
                throw RuntimeException::InvalidIssuer($issuer);
            }

            // use both the issuer parameter and label prefix as recommended by Google for BC reasons
            $label = $issuer . ':' . $label;
            $otpauthString .= '&issuer=%s';
        }

        $otpauthString = rawurlencode(sprintf($otpauthString, $label, $secret, $issuer));

        return sprintf(
            'https://api.qrserver.com/v1/create-qr-code/?size=%1$dx%1$d&data=%2$s&ecc=M',
            $size,
            $otpauthString
        );
    }

    /**
     * @param string $secret
     * @param float|string|int|\DateTimeInterface|null $time
     */
    public function getCode($secret, $time = null): string
    {
        if (null === $time) {
            $time = $this->instanceTime;
        }

        if ($time instanceof \DateTimeInterface) {
            $timeForCode = floor($time->getTimestamp() / $this->periodSize);
        } else {
            @trigger_error(
                'Passing anything other than null or a DateTimeInterface to $time is deprecated.',
                \E_USER_DEPRECATED
            );
            $timeForCode = $time;
        }

        $base32 = new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
        $secret = $base32->decode($secret);

        $timeForCode = str_pad(pack('N', $timeForCode), 8, \chr(0), \STR_PAD_LEFT);

        $hash = hash_hmac('sha1', $timeForCode, $secret, true);
        $offset = \ord(substr($hash, -1));
        $offset &= 0xF;

        $truncatedHash = $this->hashToInt($hash, $offset) & 0x7FFFFFFF;

        return str_pad((string) ($truncatedHash % $this->pinModulo), $this->passCodeLength, '0', \STR_PAD_LEFT);
    }

    private function hashToInt(string $bytes, int $start): int
    {
        return unpack('N', substr(substr($bytes, $start), 0, 4))[1];
    }
}
