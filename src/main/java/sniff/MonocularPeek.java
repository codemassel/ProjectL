package sniff;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MonocularPeek {

    private final Map<String, Boolean> activeShips = new ConcurrentHashMap<>();
    private final File scannedLogFile;
    private final File foundLogFile;
    private final File lastScannedIpFile;

    public MonocularPeek() {
        scannedLogFile = createLogFile("scanned");
        foundLogFile = createLogFile("found");
        lastScannedIpFile = new File("lastScannedIp.txt");
    }

    private File createLogFile(String type) {
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String fileName = "PirateAdventures_" + type + "_" + timeStamp + ".txt";
            String directory = "logs/" + type;
            File dir = new File(directory);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File logFile = new File(dir, fileName);
            logFile.createNewFile();
            return logFile;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void discoverShips(String startIp, String endIp, int numThreads) {
        String lastScannedIp = getLastScannedIp();
        long startIpLong;
        long endIpLong;
        try {
            startIpLong = ipToLong(InetAddress.getByName(startIp));
            endIpLong = ipToLong(InetAddress.getByName(endIp));
        } catch (UnknownHostException e) {
            throw new RuntimeException("Invalid IP address", e);
        }

        // Calculate IPs per thread
        long totalIPs = endIpLong - startIpLong + 1;
        long ipsPerThread = totalIPs / numThreads;

        Thread[] threads = new Thread[numThreads];
        for (int i = 0; i < numThreads; i++) {
            long threadStart = startIpLong + i * ipsPerThread;
            long threadEnd = i == numThreads - 1 ? endIpLong : threadStart + ipsPerThread - 1;
            threads[i] = new Thread(new ShipChecker(threadStart, threadEnd));
            threads[i].start();
        }

        // Wait for all threads to finish
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private class ShipChecker implements Runnable {
        private final long startIpLong;
        private final long endIpLong;

        public ShipChecker(long startIpLong, long endIpLong) {
            this.startIpLong = startIpLong;
            this.endIpLong = endIpLong;
        }

        @Override
        public void run() {
            for (long ip = startIpLong; ip <= endIpLong; ip++) {
                String host = longToIp(ip);
                System.out.println("Checking ship with " + host + " for weaknesses...");

                boolean isReachable = isDeviceReachable(host, 80, 5000);
                synchronized (activeShips) {
                    if (isReachable) {
                        activeShips.put(host, true);
                        System.out.println("Found ship: " + host);
                        scanTelnetPorts(host, 5000);
                    }
                    writeToLogFile(scannedLogFile, "Scanned IP: " + host);
                }
            }
        }
    }

    public void scanTelnetPorts(String host, int timeout) {
        boolean port23Open = isPortOpen(host, 23, timeout);
        boolean port2323Open = isPortOpen(host, 2323, timeout);

        synchronized (activeShips) {
            if (!port23Open && !port2323Open) {
                activeShips.remove(host);
                System.out.println("Ship : " + host + " is too strong");
            } else {
                writeToLogFile(foundLogFile, "Ruffy found a weak ship: " + host);
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                System.out.println("Ship: " + host + " is ready to get rämsed");
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
            }
        }
    }

    public static boolean isDeviceReachable(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean isPortOpen(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }

    public static String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    private void writeToLogFile(File logFile, String message) {
        synchronized (logFile) {
            try (FileWriter writer = new FileWriter(logFile, true);
                 BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
                bufferedWriter.write(message);
                bufferedWriter.newLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public synchronized String getLastScannedIp() {
        if (!lastScannedIpFile.exists()) {
            return null;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(lastScannedIpFile))) {
            return reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private synchronized void updateLastScannedIp(String ip) {
        try (FileWriter writer = new FileWriter(lastScannedIpFile)) {
            writer.write(ip);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
