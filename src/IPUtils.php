<?php
namespace Cooker\Tools\IP;

class IPUtils
{
    /**
     * 移除 CIDR IP 中包含的端口和最后部分内容
     *
     * @access public static
     * @param  string $ipString 
     * @return string
     */
    public static function sanitizeIp($ipString)
    {
        $ipString = trim($ipString);

        // CIDR notation, A.B.C.D/E
        $posSlash = strrpos($ipString, '/');
        if ($posSlash !== false) {
            $ipString = substr($ipString, 0, $posSlash);
        }

        $posColon = strrpos($ipString, ':');
        $posDot = strrpos($ipString, '.');
        if ($posColon !== false) {
            // IPv6 address with port, [A:B:C:D:E:F:G:H]:EEEE
            $posRBrac = strrpos($ipString, ']');
            if ($posRBrac !== false && $ipString[0] == '[') {
                $ipString = substr($ipString, 1, $posRBrac - 1);
            }

            if ($posDot !== false) {
                // IPv4 address with port, A.B.C.D:EEEE
                if ($posColon > $posDot) {
                    $ipString = substr($ipString, 0, $posColon);
                }
                // else: Dotted quad IPv6 address, A:B:C:D:E:F:G.H.I.J
            } else if (strpos($ipString, ':') === $posColon) {
                $ipString = substr($ipString, 0, $posColon);
            }
            // else: IPv6 address, A:B:C:D:E:F:G:H
        }
        // else: IPv4 address, A.B.C.D

        return $ipString;
    }

    /**
     * 净化IP地址范围
     *
     * 1. single IPv4 address, e.g., 127.0.0.1
     * 2. single IPv6 address, e.g., ::1/128
     * 3. IPv4 block using CIDR notation, e.g., 192.168.0.0/22 represents the IPv4 addresses from 192.168.0.0 to 192.168.3.255
     * 4. IPv6 block using CIDR notation, e.g., 2001:DB8::/48 represents the IPv6 addresses from 2001:DB8:0:0:0:0:0:0 to 2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF
     * 5. wildcards, e.g., 192.168.0.* or 2001:DB8:*:*:*:*:*:*
     *
     * @access public 
     * @param string $ipRangeString 
     * @return string|null  
     */

    public static function sanitizeIpRange($ipRangeString)
    {
        $ipRangeString = trim($ipRangeString);
        if (empty($ipRangeString)) {
            return null;
        }

        // wildcards '*'
        if (strpos($ipRangeString, '*') !== false) {
            // Disallow prefixed wildcards and anything other than wildcards
            // and separators (including IPv6 zero groups) after first wildcard
            if (preg_match('/[^.:]\*|\*.*([^.:*]|::)/', $ipRangeString)) {
                return null;
            }

            $numWildcards = substr_count($ipRangeString, '*');
            $ipRangeString = str_replace('*', '0', $ipRangeString);

            // CIDR
        } elseif (($pos = strpos($ipRangeString, '/')) !== false) {
            $bits = substr($ipRangeString, $pos + 1);
            $ipRangeString = substr($ipRangeString, 0, $pos);

            if (!is_numeric($bits)) {
                return null;
            }
        }

        // single IP
        if (($ip = @inet_pton($ipRangeString)) === false)
            return null;

        $maxbits = strlen($ip) * 8;
        if (!isset($bits)) {
            $bits = $maxbits;

            if (isset($numWildcards)) {
                $bits -= ($maxbits === 32 ? 8 : 16) * $numWildcards;
            }
        }

        if ($bits < 0 || $bits > $maxbits) {
            return null;
        }

        return "$ipRangeString/$bits";
    }

    /**
     * @access public 
     * @param  string $ipString 
     * @return string Binary-safe IP 
     */
    public static function stringToBinaryIP($ipString)
    {
        $ip = @inet_pton($ipString);
        return $ip === false ? "\x00\x00\x00\x00" : $ip;
    }

    /**
     * @access public 
     * @param  string $ip 
     * @return string 
     */
    public static function binaryToStringIP($ip)
    {
        $ipStr = @inet_ntop($ip);
        return $ipStr === false ? '0.0.0.0' : $ipStr;
    }

    /**
     * 取得IP地址的高位和低位
     * 
     * @access public 
     * @param  string $ipRange `'192.168.1.1/24'`.
     * @return array|null Array `array($lowIp, $highIp)` 
     */
    public static function getIPRangeBounds($ipRange)
    {
        if (strpos($ipRange, '/') === false) {
            $ipRange = self::sanitizeIpRange($ipRange);

            if ($ipRange === null) {
                return null;
            }
        }
        $pos = strpos($ipRange, '/');

        $bits = substr($ipRange, $pos + 1);
        $range = substr($ipRange, 0, $pos);
        $high = $low = @inet_pton($range);
        if ($low === false) {
            return null;
        }

        $lowLen = strlen($low);
        $i = $lowLen - 1;
        $bits = $lowLen * 8 - $bits;

        for ($n = (int)($bits / 8); $n > 0; $n--, $i--) {
            $low[$i] = chr(0);
            $high[$i] = chr(255);
        }

        $n = $bits % 8;
        if ($n) {
            $low[$i] = chr(ord($low[$i]) & ~((1 << $n) - 1));
            $high[$i] = chr(ord($high[$i]) | ((1 << $n) - 1));
        }

        return array($low, $high);
    }
}
