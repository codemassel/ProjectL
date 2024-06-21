package sniff;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Blacklist {

    private final String[] dodList = {"6.", "7.", "11.", "21.", "22.", "26.", "28.", "29.", "30.", "33.", "55.", "214.", "215."};

    protected void checkIfEnemyIsOnBlacklist(String host, long startIp, long endIp) {
        String[] dodList = {"6.", "7.", "11.", "21.", "22.", "26.", "28.", "29.", "30.", "33.", "55.", "214.", "215."};

        try {
            if (InetAddress.getByName(host).isLoopbackAddress()) {
                System.out.println("Loopback address, skipping...");
            } else if (host.startsWith("0.")) {
                System.out.println("Invalid address space, skipping...");
            } else if (host.startsWith("3.")) {
                System.out.println("General Electric Company, skipping...");
            } else if (host.startsWith("15.") || host.startsWith("16.")) {
                System.out.println("Hewlett-Packard Company, skipping...");
            } else if (host.startsWith("56.")) {
                System.out.println("US Postal Service, skipping...");
            } else if (host.startsWith("10.") || host.startsWith("192.168.")) {
                System.out.println("internal networks, skipping...");
            } else if ((host.startsWith("172.") && isInRange(host, "172.16.0.0", "172.31.255.255"))) {
                System.out.println("internal networks, skipping...");
            } else if ((host.startsWith("100.") && isInRange(host, "100.64.0.0", "100.127.255.255"))) {
                System.out.println("IANA NAT, skipping...");
            } else if ((host.startsWith("169.") && isInRange(host, "169.254.0.0", "169.254.255.255"))) {
                System.out.println("IANA NAT, skipping...");
            } else if ((host.startsWith("198.") && isInRange(host, "198.18.0.0", "198.19.255.255"))) {
                System.out.println("IANA Special use, skipping...");
            } else {
                for (String dodIp : dodList) {
                    if (host.startsWith(dodIp)) {
                        System.out.println("Department of Defense, skipping...");
                        return;
                    }
                }
            }
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isInRange(String ipAddress, String startRange, String endRange) throws UnknownHostException {
        InetAddress start = InetAddress.getByName(startRange);
        InetAddress end = InetAddress.getByName(endRange);
        InetAddress ip = InetAddress.getByName(ipAddress);

        long startLong = ipToLong(start);
        long endLong = ipToLong(end);
        long ipLong = ipToLong(ip);

        return (ipLong >= startLong && ipLong <= endLong);
    }

    private long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }

    public String[] getDodList() {
        return dodList;
    }
}
