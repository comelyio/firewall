<?php
declare(strict_types=1);

namespace Comely;

use Comely\Firewall\Blocked;
use Comely\Firewall\Constants;
use Comely\Firewall\Schema\IPGrid;
use Comely\Firewall\Vendor\CloudFlare;
use Comely\IO\Cache\Cache;
use Comely\IO\Database\Database;
use Comely\IO\Http\Request;

/**
 * Class WAF
 * @package Comely
 */
class WAF implements Constants
{
    /** @var Database */
    private $db;
    /** @var int */
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
            throw new FirewallException('Failed to connect with SQLite database');
        }

        // Cache
        if($cache) {
            $this->useCache($cache);
        }

        // Other values
        $this->rateLimiting =   60;
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
     * @param string $ipAddress
     * @param Request $req
     * @param Request\Response|null $res
     * @throws FirewallException
     */
    public function handleHttpRequest(string $ipAddress, Request $req, Request\Response $res = null)
    {
        // Check if IP blocked in cache
        $cacheChecked   =   false;
        $cacheIpKey =   sprintf('waf:ip_%s', $ipAddress);
        if($this->cache) {
            try {
                $blocked    =   $this->cache->get($cacheIpKey);
                if($blocked) {
                    Blocked::RateLimiting($res);
                }
                $cacheChecked   =   true;
            } catch (\Exception $e) {
            }
        }

        if(!$cacheChecked) {
            // Todo: Check in DB in blocked IPs table, and save in Cache
        }

        // Log
        $this->db->table(IPGrid::SCHEMA_TABLE)
            ->insert([
                "method"    =>  $req ? $req->getMethod() ?? null : null,
                "ip_address"    =>  $ipAddress,
                "second"    =>  time(),
                "micro_time"    =>  microtime(true)
            ]);
        if(!$this->db->lastQuery->rows) {
            throw new FirewallException('Failed to log this HTTP request in IP grid');
        }
    }
}