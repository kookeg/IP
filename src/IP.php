<?php

namespace Cooker\Tools\IP;

/**
 * IP 地址类.
 */

abstract class IP
{
    /**
     * IP 二进制.
     *
     * @var string
     */
    protected $ip;

    /**
     * @param string $ip 
     */
    protected function __construct($ip)
    {
        $this->ip = $ip;
    }

    /**
     * 根据二进制IP创建IP实例 
     *
     * @access public static
     * @param  string $ip 
     * @return IP
     */

    public static function fromBinaryIP($ip)
    {
        if (is_null($ip) || trim($ip) === '') {
            return new IPv4("\x00\x00\x00\x00");
        }

        if (self::isIPv4($ip)) {
            return new IPv4($ip);
        }

        return new IPv6($ip);
    }

    /**
     * 根据字符串IP创建IP实例
     *
     * @access public  static
     * @param  string $ip 
     * @return IP
     */

    public static function fromStringIP($ip)
    {
        return self::fromBinaryIP(IPUtils::stringToBinaryIP($ip));
    }

    /**
     * 返回二进制IP 
     *
     * @access public 
     * @return string
     */

    public function toBinary()
    {
        return $this->ip;
    }

    /**
     * 返回字符串IP
     *
     * @access public 
     * @return string
     */

    public function toString()
    {
        return IPUtils::binaryToStringIP($this->ip);
    }

    public function __toString()
    {
        return $this->toString();
    }

    /**
     * 尝试通过DNS解析返回IP对应的host 
     *
     * @access public 
     * @return string|null 
     */
    public function getHostname()
    {
        $stringIp = $this->toString();

        $host = strtolower(@gethostbyaddr($stringIp));

        if ($host === '' || $host === $stringIp) {
            return null;
        }
        return $host;
    }

    /**
     * 判断某个IP是否在某段IP范围内 
     *
     *
     * @access public 
     * @param  string 
     * @return bool
     */

    public function isInRange($ipRange)
    {
        $ipLen = strlen($this->ip);
        if (empty($this->ip) || empty($ipRange) || ($ipLen != 4 && $ipLen != 16)) {
            return false;
        }

        if (is_array($ipRange)) {
            // already split into low/high IP addresses
            $ipRange[0] = IPUtils::stringToBinaryIP($ipRange[0]);
            $ipRange[1] = IPUtils::stringToBinaryIP($ipRange[1]);
        } else {
            // expect CIDR format but handle some variations
            $ipRange = IPUtils::getIPRangeBounds($ipRange);
        }
        if ($ipRange === null) {
            return false;
        }

        $low = $ipRange[0];
        $high = $ipRange[1];
        if (strlen($low) != $ipLen) {
            return false;
        }

        // binary-safe string comparison
        if ($this->ip >= $low && $this->ip <= $high) {
            return true;
        }

        return false;
    }

    /**
     * 判断某个IP是否在某段IP范围内 
     *
     *
     * @access public 
     * @param  array
     * @return bool
     */

    public function isInRanges(array $ipRanges)
    {
        $ipLen = strlen($this->ip);
        if (empty($this->ip) || empty($ipRanges) || ($ipLen != 4 && $ipLen != 16)) {
            return false;
        }

        foreach ($ipRanges as $ipRange) {
            if ($this->isInRange($ipRange)) {
                return true;
            }
        }

        return false;
    }

    public abstract function toIPv4String();
    public abstract function anonymize($byteCount);

    private static function isIPv4($binaryIp)
    {
        $strlen = function_exists('mb_orig_strlen') ? 'mb_orig_strlen' : 'strlen';
        return (int)$strlen($binaryIp) === 4;
    }
}
