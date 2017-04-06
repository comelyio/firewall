<?php
declare(strict_types=1);

namespace Comely\Firewall\Rules;

/**
 * Class RateLimiting
 * @package Comely\Firewall\Rules
 */
class RateLimiting
{
    /** @var int */
    public $limit;
    /** @var int */
    public $ttl;

    /**
     * RateLimiting constructor.
     * @param int $limit
     * @param int $ttl
     */
    public function __construct(int $limit, int $ttl)
    {
        $this->limit    =   $limit;
        $this->ttl  =   $ttl;
    }
}