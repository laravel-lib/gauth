# Google Authenticator for Laravel

## Installation

```bash
composer require laravel-lib/gauth
```

## Usage

To generate secret code

```
$secret_code = GAuth::generateSecret();
```

To generate QR Code URL image

```
$secret_code = GAuth::generateSecret();
$qrcode_img_url = GAuth::generateQrUrl('foo@bar.com', $secret_code, 'My App Name); // No semicolon (:) on App Name
```

To check the qrcode

```
$secret_code = GAuth::generateSecret();

$user_input = '123456';

if (!GAuth::checkCode($secret_code, $user_input)) {
    die('The code is invalid !');
    return;
}
```

To get current code

```
$secret_code = GAuth::generateSecret();

$current_code = GAuth::getCode($secret_code);
```
