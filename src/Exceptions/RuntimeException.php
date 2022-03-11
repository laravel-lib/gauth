<?php

namespace LaravelLib\GAuth\Exceptions;

final class RuntimeException extends \RuntimeException
{
    public static function InvalidAccountName(string $accountName): self
    {
        return new self(sprintf(
            'The account name may not contain a double colon (:) and may not be an empty string. Given "%s".',
            $accountName
        ));
    }

    public static function InvalidIssuer(string $issuer): self
    {
        return new self(sprintf(
            'The issuer name may not contain a double colon (:) and may not be an empty string. Given "%s".',
            $issuer
        ));
    }

    public static function InvalidSecret(): self
    {
        return new self('The secret name may not be an empty string.');
    }
}
