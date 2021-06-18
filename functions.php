<?php

$ipRanges = [
'173.245.48.0/20',
'103.21.244.0/22',
'103.22.200.0/22',
'103.31.4.0/22',
'141.101.64.0/18',
'108.162.192.0/18',
'190.93.240.0/20',
'188.114.96.0/20',
'197.234.240.0/22',
'198.41.128.0/17',
'162.158.0.0/15',
'172.64.0.0/13',
'131.0.72.0/22',
'104.16.0.0/13',
'104.24.0.0/14',
'2400:cb00::/32',
'2606:4700::/32',
'2803:f800::/32',
'2405:b500::/32',
'2405:8100::/32',
'2a06:98c0::/29',
'2c0f:f248::/32',
];

function ipCheck($replace_ip = false)
{
    $ip = $_SERVER['REMOTE_ADDR'];
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        foreach ($ipRanges as $ipRange) {
            if (IPCheck_CloudFlare_Match($ip, $ipRange)) {
                if ($replace_ip) {
                    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
                }

                return $_SERVER['HTTP_CF_CONNECTING_IP'];
            }
        }
    }

    return $ip;
}

if (!function_exists('IPCheck_MatchIpToCidr')) {
    function IPCheck_MatchIpToCidr($ip, $cidr)
    {
        $c = explode('/', $cidr);
        $subnet = isset($c[0]) ? $c[0] : null;
        $mask = isset($c[1]) ? $c[1] : null;
        if ($mask === null) {
            $mask = 32;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // it's valid
            $ipVersion = 'v4';
        } else {
            // it's not valid
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                // it's valid
                $ipVersion = 'v6';
            } else {
                // it's not valid
                return false;
            }
        }

        switch ($ipVersion) {
        case 'v4':
            return IPCheck_IPv4Match($ip, $subnet, $mask);
            break;
        case 'v6':
            return IPCheck_IPv6Match($ip, $subnet, $mask);
            break;
    }
    }
}

if (!function_exists('IPCheck_IPv4Match')) {
    function IPCheck_IPv4Match($address, $subnetAddress, $subnetMask)
    {
        if (!filter_var($subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $subnetMask === null || $subnetMask === '' || $subnetMask < 0 || $subnetMask > 32) {
            return false;
        }

        $address = ip2long($address);
        $subnetAddress = ip2long($subnetAddress);
        $mask = -1 << (32 - $subnetMask);
        $subnetAddress &= $mask;

        return ($address & $mask) == $subnetAddress;
    }
}

if (!function_exists('IPCheck_IPv6Match')) {
    function IPCheck_IPv6Match($address, $subnetAddress, $subnetMask)
    {
        if (!filter_var($subnetAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || $subnetMask === null || $subnetMask === '' || $subnetMask < 0 || $subnetMask > 128) {
            return false;
        }
        $subnet = inet_pton($subnetAddress);
        $addr = inet_pton($address);

        $binMask = IPCheck_IPv6MaskToByteArray($subnetMask);

        return ($addr & $binMask) == $subnet;
    }
}

if (!function_exists('IPCheck_IPv6MaskToByteArray')) {
    function IPCheck_IPv6MaskToByteArray($subnetMask)
    {
        $addr = str_repeat('f', $subnetMask / 4);
        switch ($subnetMask % 4) {
        case 0:
            break;
        case 1:
            $addr .= '8';
            break;
        case 2:
            $addr .= 'c';
            break;
        case 3:
            $addr .= 'e';
            break;
    }
        $addr = str_pad($addr, 32, '0');
        $addr = pack('H*', $addr);

        return $addr;
    }
}
