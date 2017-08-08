<?php
namespace Cooker\Tools\IP;

/**
 * IP v4 地址.
 */

class IPv4 extends IP
{
    /**
     * {@inheritdoc}
     */
    public function toIPv4String()
    {
        return $this->toString();
    }

    /**
     * {@inheritdoc}
     */
    public function anonymize($byteCount)
    {
        $newBinaryIp = $this->ip;

        $i = strlen($newBinaryIp);
        if ($byteCount > $i) {
            $byteCount = $i;
        }

        while ($byteCount-- > 0) {
            $newBinaryIp[--$i] = chr(0);
        }

        return self::fromBinaryIP($newBinaryIp);
    }
}
