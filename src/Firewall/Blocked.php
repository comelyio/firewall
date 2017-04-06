<?php
declare(strict_types=1);

namespace Comely\Firewall;

use Comely\IO\Http\Request\Response;
use Comely\WAF;

/**
 * Class Blocked
 * @package Comely\Firewall
 */
class Blocked
{
    /**
     * @param Response|null $response
     */
    public static function RateLimiting(Response $response = null)
    {
        if($response) {
            $response->setCode(429);
        }

        self::Display(429, 'Rate Limiting', 'Slow down a little! Too many requests');
    }

    /**
     * @param int $code
     * @param string $heading
     * @param string|null $descr
     */
    private static function Display(int $code, string $heading, string $descr = null)
    {
        printf('<h1>%s</h1>%s', $code, $heading, PHP_EOL);
        if($descr) {
            printf('<p>%s</p>%s', $descr, PHP_EOL);
        }

        printf(
            '<hr>%s<a href="https://github.com/comelyio/firewall" target="_blank">Comely WAF %s</a>',
            PHP_EOL,
            WAF::VERSION
        );
        exit();
    }
}