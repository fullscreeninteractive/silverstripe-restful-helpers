<?php

namespace FullscreenInteractive\Restful\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * Tracks a per member token version. Tokens embed the version they were issued
 * with (the "ver" claim) so incrementing it revokes every existing token.
 *
 * @extends Extension<Member>
 */
class JWTMemberExtension extends Extension
{
    private static $db = [
        'JWTTokenVersion' => 'Int'
    ];

    protected function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName('JWTTokenVersion');
    }

    /**
     * Changing a password revokes all tokens issued with the old one.
     */
    protected function onBeforeWrite()
    {
        if ($this->owner->isInDB() && $this->owner->isChanged('Password', DataObject::CHANGE_VALUE)) {
            $this->owner->JWTTokenVersion = (int) $this->owner->JWTTokenVersion + 1;
        }
    }
}
