<?php
namespace Cooker\Tools\IP;

/**
 * IP v6 地址.
 */

class IPv6 extends IP
{
    const MAPPED_IPv4_START = '::ffff:';

    /**
     * {@inheritdoc}
     */
    public function anonymize($byteCount)
    {
        $newBinaryIp = $this->ip;

        if ($this->isMappedIPv4()) {
            $i = strlen($newBinaryIp);
            if ($byteCount > $i) {
                $byteCount = $i;
            }

            while ($byteCount-- > 0) {
                $newBinaryIp[--$i] = chr(0);
            }

            return self::fromBinaryIP($newBinaryIp);
        }

        $masks = array(
            'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            'ffff:ffff:ffff:ffff::',
            'ffff:ffff:ffff:0000::',
            'ffff:ff00:0000:0000::'
        );

        $newBinaryIp = $newBinaryIp & pack('a16', inet_pton($masks[$byteCount]));

        return self::fromBinaryIP($newBinaryIp);
    }

    /**
     * {@inheritdoc}
     */
    public function toIPv4String()
    {
        $str = $this->toString();

        if ($this->isMappedIPv4()) {
            return substr($str, strlen(self::MAPPED_IPv4_START));
        }

        return null;
    }

    public function isMappedIPv4()
    {
        return substr_compare($this->ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 0, 12) === 0
            || substr_compare($this->ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 0, 12) === 0;
    }
}
