<?php

namespace Juzaweb\Permissions\Exceptions;

use InvalidArgumentException;

class PermissionDoesNotExist extends InvalidArgumentException
{
    public static function create(string $permissionName, string $guardName = '')
    {
        return new static("There is no permission named `{$permissionName}` for guard `{$guardName}`.");
    }

    public static function withId(int $permissionId, string $guardName = ''): static
    {
        return new static("There is no [permission] with id `{$permissionId}` for guard `{$guardName}`.");
    }
}
