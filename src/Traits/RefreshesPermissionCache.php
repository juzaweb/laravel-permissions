<?php

namespace Juzaweb\Permissions\Traits;

use Juzaweb\Permissions\PermissionRegistrar;

trait RefreshesPermissionCache
{
    public static function bootRefreshesPermissionCache(): void
    {
        static::saved(
            function () {
                app(PermissionRegistrar::class)->forgetCachedPermissions();
            }
        );

        static::deleted(
            function () {
                app(PermissionRegistrar::class)->forgetCachedPermissions();
            }
        );
    }
}
