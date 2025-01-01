/*
 * Created by Dean Stevick <dfaworks@gmail.com> on December 8, 2024
 *
 * Copyright © 2025 BEAR, Inc.  All Rights Reserved.
 */
package netzbegruenung.keycloak.authenticator;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * IP address utilities for convert to long and compare
 */
public class IpUtils {

    private static long ipToLong( InetAddress ip ) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for ( byte octet : octets ) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    public static boolean isEqual( String ip1, String ip2 ) {
        try {
            long lIp1 = ipToLong( InetAddress.getByName( ip1 ) );
            long lIp2 = ipToLong( InetAddress.getByName( ip2 ) );
            return ( lIp1 == lIp2 );
        }
        catch ( UnknownHostException e ) {
            return false;
        }
    }

}
