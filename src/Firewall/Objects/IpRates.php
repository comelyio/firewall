<?php
declare(strict_types=1);

namespace Comely\Firewall\Objects;

/**
 * Class IpRates
 * @package Comely\Firewall\Object
 */
class IpRates implements \Countable
{
    /** @var array */
    private $rows;
    /** @var int */
    private $count;

    /**
     * IpRates constructor.
     */
    public function __construct()
    {
        $this->rows =   [];
        $this->count    =   0;
    }

    /**
     * @param string $ipAddress
     * @param int $count
     */
    public function add(string $ipAddress, int $count)
    {
        $this->rows[]   =   [
            "ip"    =>  $ipAddress,
            "count" =>  $count
        ];
        $this->count++;
    }

    /**
     * @return array
     */
    public function get() : array
    {
        return $this->rows;
    }

    /**
     * @return int
     */
    public function count() : int
    {
        return $this->count;
    }
}