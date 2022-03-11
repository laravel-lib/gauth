<?php

namespace LaravelLib\GAuth;

use LaravelLib\GAuth\Facades\GAuth;
use Illuminate\Support\ServiceProvider;

class GAuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->bind('gauth', function () {
            return new GAuth;
        });
    }
}
