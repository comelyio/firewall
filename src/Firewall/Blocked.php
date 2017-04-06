<?php
declare(strict_types=1);

namespace Comely\Firewall;

/**
 * Class Blocked
 * @package Comely\Firewall
 */
class Blocked
{
    public static function Screen(int $code)
    {
        switch ($code) {
            case 429:
                @http_response_code(429);
                self::Display(429, 'Rate Limiting', 'Slow down a little! Too many requests');
                exit;
            default:
                @http_response_code(403);
                self::Display(403, 'Forbidden', 'Your IP address has been blocked from accessing this endpoint');
        }
    }

    /**
     * @param int $code
     * @param string $heading
     * @param string|null $descr
     */
    private static function Display(int $code, string $heading, string $descr = null)
    {
        printf('<h1>%d &ndash; %s</h1>%s', $code, $heading, PHP_EOL);
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