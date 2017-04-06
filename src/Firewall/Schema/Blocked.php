<?php
declare(strict_types=1);

namespace Comely\Firewall\Schema;

use Comely\IO\Database\Exception\SchemaException;
use Comely\IO\Database\Schema\AbstractTable;

/**
 * Class Blocked
 * @package Comely\Firewall\Schema
 */
class Blocked extends AbstractTable
{
    const SCHEMA_TABLE  =   "blocked";
    const SCHEMA_MODEL  =   null;

    /**
     * @throws SchemaException
     */
    public function createTable()
    {
        $this->string("ip_address", 45, self::STR_VARIABLE)->unique();
        $this->int("rule", self::INT_TINY)->unSigned();
        $this->int("ttl", self::INT_DEFAULT)->unSigned();
        $this->int("added", self::INT_DEFAULT)->unSigned();
    }
}