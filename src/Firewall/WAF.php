<?php
declare(strict_types=1);

namespace Comely\Firewall;

use Comely\Firewall\Objects\IpRates;
use Comely\Firewall\Rules\RateLimiting;
use Comely\Firewall\Schema\IPGrid;
use Comely\Firewall\Vendor\CloudFlare;
use Comely\IO\Cache\Cache;
use Comely\IO\Database\Database;
use Comely\IO\Database\Schema;

/**
 * Class WAF
 * @package Comely
 */
class WAF implements Constants
{
    /** @var Database */
    private $db;
    /** @var int */
    private $rulesCount;
    /** @var null|RateLimiting */
    private $rateLimiting;
    /** @var null|Cache */
    private $cache;
    /** @var null|CloudFlare */
    private $cloudFlare;

    /**
     * WAF constructor.
     * @param string $dbPath
     * @param Cache|null $cache
     * @throws FirewallException
     */
    public function __construct(string $dbPath, Cache $cache = null)
    {
        // Connect to SQLite Database
        try {
            $this->db   =   new Database("sqlite", $dbPath);
        } catch (\Exception $e) {
            throw new FirewallException(__METHOD__, 'Failed to connect with SQLite database');
        }

        $this->rulesCount   =   0;

        // Cache
        if($cache) {
            $this->useCache($cache);
        }

    }

    /**
     * @param Cache $cache
     * @return WAF
     */
    public function useCache(Cache $cache) : self
    {
        $this->cache    =   $cache;
        return $this;
    }

    /**
     * @param CloudFlare $cf
     * @return WAF
     */
    public function useCloudFlare(CloudFlare $cf) : self
    {
        $this->cloudFlare   =   $cf;
        return $this;
    }

    /**
     * @param int $limit
     * @param int $ttl
     * @return WAF
     */
    public function rateLimiting(int $limit, int $ttl) : self
    {
        $this->rateLimiting =   new RateLimiting($limit, $ttl);
        $this->rulesCount++;
        return $this;
    }

    /**
     *
     */
    public function rebuildSQLiteDB()
    {
        Schema::loadTable($this->db, 'Comely\Firewall\Schema\IPGrid');
        Schema::loadTable($this->db, 'Comely\Firewall\Schema\Blocked');

        /** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
        $tables =   [
            IPGrid::SCHEMA_TABLE,
            \Comely\Firewall\Schema\Blocked::SCHEMA_TABLE
        ];
        foreach($tables as $table) {
            try {
                $this->db->query(
                    Schema::getTable($table)->tableBuilder(false),
                    [],
                    Database::QUERY_EXEC
                );
            } catch (\Exception $e) {
            }
        }
    }

    /**
     * @param string $ipAddress
     * @param string|null $httpMethod
     * @return bool
     * @throws FirewallException
     */
    public function handleHttpRequest(string $ipAddress, string $httpMethod = null) : bool
    {
        // Check if IP blocked in cache
        $cacheChecked   =   false;
        $cacheIpKey =   sprintf('waf:ip_%s', $ipAddress);
        if($this->cache) {
            try {
                $blocked    =   $this->cache->get($cacheIpKey);
                if($blocked) {
                    Blocked::Screen(intval($blocked));
                }
                $cacheChecked   =   true;
            } catch (\Exception $e) {
            }
        }

        if(!$cacheChecked) {
            /** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
            $blockedList    =   \Comely\Firewall\Schema\Blocked::SCHEMA_TABLE;
            $blocked    =   $this->db->table($blockedList)
                ->find('`ip_address`=?', [$ipAddress])
                ->fetchFirst();
            if(is_array($blocked)) {
                $rule   =   intval($blocked["rule"] ?? -1);
                $addedOn    =   intval($blocked["added"] ?? -1);
                $ttl    =   intval($blocked["ttl"] ?? -1);
                if($ttl !== 0) {
                    $ttl    =   ($addedOn+$ttl)-time();
                }

                if($rule    <=  0   ||  $ttl    <  0) {
                    // Delete from blocked list
                    $delete =   $this->db->table($blockedList)
                        ->find('`ip_address`=?', [$ipAddress])
                        ->delete();
                } else {
                    // Save in cache
                    if($this->cache) {
                        try {
                            $this->cache->set($cacheIpKey, $rule, $ttl);
                        } catch (\Exception $e) {
                            trigger_error(
                                $e->getMessage(),
                                E_USER_WARNING
                            );
                        }
                    }

                    // Show blocked screen
                    Blocked::Screen($rule);
                }
            }
        }

        // Check Rules Count
        if(!$this->rulesCount) {
            return false;
        }

        // Log
        $this->db->table(IPGrid::SCHEMA_TABLE)
            ->insert([
                "method"    =>  $httpMethod ? strtoupper($httpMethod) : null,
                "ip_address"    =>  $ipAddress,
                "second"    =>  time(),
                "micro_time"    =>  microtime(true)
            ]);
        if(!$this->db->lastQuery->rows) {
            throw new FirewallException(__METHOD__, 'Failed to log this HTTP request in IP grid');
        }

        return true;
    }

    /**
     * @param int|null $timeStamp
     * @return int
     */
    public function flushIpGrid(int $timeStamp = null) : int
    {
        if(!$timeStamp) {
            $timeStamp  =   time();
        }

        $this->db->table(IPGrid::SCHEMA_TABLE)
            ->find("`second`<=?", [$timeStamp])
            ->delete();

        return $this->db->lastQuery->rows;
    }

    /**
     * @param int|null $timeStamp
     * @return IpRates
     */
    public function crunchIpRates(int $timeStamp = null) : IpRates
    {
        if(!$timeStamp) {
            $timeStamp  =   time();
        }

        $ipRates    =   new IpRates();
        $rows   =   $this->db->query(
            sprintf(
                'SELECT' . ' count(*),`ip_address` FROM `%1$s` WHERE `second`<? GROUP BY `ip_address`',
                IPGrid::SCHEMA_TABLE
            ),
            [
                $timeStamp
            ],
            Database::QUERY_FETCH
        );

        if(is_array($rows)) {
            foreach ($rows as $row) {
                $ip =   $row["ip_address"] ?? null;
                $count  =   intval($row["count(*)"] ?? -1);
                if(is_string($ip)   &&  $count  >   0) {
                    $ipRates->add($ip, $count);
                }
            } unset($ip, $count);
        }

        return $ipRates;
    }

    /**
     * @param IpRates $ipRates
     * @param bool $throw
     * @return int
     * @throws \Exception
     */
    public function blockIpRates(IpRates $ipRates, bool $throw = false) : int
    {
        $blocked    =   0;
        if($this->rateLimiting) {
            $ipRates    =   $ipRates->get();
            foreach($ipRates as $entry) {
                if($entry["count"]  >=  $this->rateLimiting->limit) {
                    try {
                        $this->blockIP($entry["ip"], 429, $this->rateLimiting->ttl);
                    } catch (\Exception $e) {
                        if($throw) {
                            throw $e;
                        } else {
                            trigger_error(
                                $e->getMessage(),
                                E_USER_WARNING
                            );
                        }
                    }
                }
            }
        }

        return $blocked;
    }

    /**
     * @param string $ip
     * @param int $code
     * @param int $ttl
     * @return bool
     * @throws FirewallException
     */
    public function blockIP(string $ip, int $code, int $ttl) : bool
    {
        /** @noinspection PhpUnnecessaryFullyQualifiedNameInspection */
        $this->db->query(
            sprintf(
                'INSERT OR REPLACE INTO `%1$s` (`ip_address`, `rule`, `ttl`, `added`) VALUES (:ip_address, :rule, :ttl, :added)',
                \Comely\Firewall\Schema\Blocked::SCHEMA_TABLE
            ),
            [
                "ip_address"    =>  $ip,
                "rule"  =>  $code,
                "ttl"   =>  $ttl,
                "added" =>  time()
            ],
            Database::QUERY_EXEC
        );
        if(!$this->db->lastQuery->rows) {
            throw new FirewallException(
                __METHOD__,
                sprintf('Failed to add IP %1$s in blocked list', $ip)
            );
        }

        // Add to cache
        if($this->cache) {
            try {
                $this->cache->set(
                    sprintf('waf:ip_%s', $ip),
                    $code,
                    $ttl
                );
            } catch (\Exception $e) {
                trigger_error(
                    $e->getMessage(),
                    E_USER_WARNING
                );
            }
        }

        return true;
    }
}