<?php
declare(strict_types=1);

namespace Comely\Firewall\Vendor;

/**
 * Class CloudFlare
 * @package Comely\Firewall\Vendor
 */
class CloudFlare
{
    /** @var string */
    private $email;
    /** @var string */
    private $apiKey;
    /** @var string|null */
    private $userServiceKey;

    /**
     * CloudFlare constructor.
     * @param string $email
     * @param string $apiKey
     * @param string|null $userServiceKey
     */
    public function __construct(string $email, string $apiKey, string $userServiceKey = null)
    {
        $this->email    =   $email;
        $this->apiKey   =   $apiKey;
        $this->userServiceKey   =   $userServiceKey;
    }
}