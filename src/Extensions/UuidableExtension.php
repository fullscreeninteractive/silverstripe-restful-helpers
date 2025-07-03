<?php

namespace FullscreenInteractive\Restful\Extensions;

use Ramsey\Uuid\Uuid;
use SilverStripe\Core\Extension;

class UuidableExtension extends Extension
{
    private static $db = [
        'UUID' => 'Varchar(200)'
    ];

    private static $indexes = [
        'UUID' => true
    ];

    public function onBeforeWrite()
    {
        if (!$this->owner->UUID) {
            $this->owner->UUID = Uuid::uuid4()->toString();
        }
    }
}
