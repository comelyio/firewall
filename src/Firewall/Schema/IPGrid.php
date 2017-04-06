<?php
declare(strict_types=1);

namespace Comely\Firewall\Schema;

use Comely\IO\Database\Exception\SchemaException;
use Comely\IO\Database\Schema\AbstractTable;

/**
 * Class IPGrid
 * @package Comely\Firewall\Schema
 */
class IPGrid extends AbstractTable
{
    const SCHEMA_TABLE  =   "ip_grid";
    const SCHEMA_MODEL  =   null;

    /**
     * @throws SchemaException
     */
    public function createTable()
    {
        $this->string("method", 6, self::STR_VARIABLE)->nullable();
        $this->string("ip_address", 45, self::STR_VARIABLE);
        $this->int("second", self::INT_DEFAULT)->unSigned();
        $this->string("micro_time", 15, self::STR_FIXED);
    }
}