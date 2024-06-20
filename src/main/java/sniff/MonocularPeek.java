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

    public MonocularPeek() {
        scannedLogFile = createLogFile("scanned");
        foundLogFile = createLogFile("found");
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

        long startIpLong;
        long endIpLong;
        try {
            startIpLong = ipToLong(InetAddress.getByName(startIp));
            endIpLong = ipToLong(InetAddress.getByName(endIp));
        } catch (UnknownHostException e) {
            throw new RuntimeException("Invalid IP address", e);
        }

        long totalIPs = endIpLong - startIpLong + 1;
        long ipsPerThread = totalIPs / numThreads;

        Thread[] threads = new Thread[numThreads];
        for (int i = 0; i < numThreads; i++) {
            long threadStart = startIpLong + i * ipsPerThread;
            long threadEnd = i == numThreads - 1 ? endIpLong : threadStart + ipsPerThread - 1;
            threads[i] = new Thread(new ShipChecker(threadStart, threadEnd));
            threads[i].start();
        }

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
        boolean port23Open = isPortOpen(host, timeout);

        synchronized (activeShips) {
            if (!port23Open) {
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

    public static boolean isPortOpen(String host, int timeout) {
        if (!isDeviceReachable(host, 23, timeout)) {
            return false;
        }

        try (Socket telnetSocket = new Socket()) {
            telnetSocket.connect(new java.net.InetSocketAddress(host, 23), timeout);

            // sends data
            OutputStream out = telnetSocket.getOutputStream();
            // gets data
            InputStream in = telnetSocket.getInputStream();

            //send simple telnet request
            out.write("hello\n".getBytes());
            out.flush();

            // wait 1sec
            Thread.sleep(timeout);

            // checks if data is found
            if (in.available() > 0) {
                byte[] buffer = new byte[1024];
                int bytesRead = in.read(buffer);
                if (bytesRead > 0) {
                    String response = new String(buffer, 0, bytesRead);
                    System.out.println("Received: " + response);
                    return true;
                }
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }

        return false;
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
        File logDir = new File("logs/scanned");
        File[] logFiles = logDir.listFiles((dir, name) -> name.startsWith("PirateAdventures_scanned_"));
        if (logFiles == null || logFiles.length < 1) {
            return null;
        }
        File latestChangedLogFile = logFiles[0];

        for (File logFile : logFiles) {
            if (latestChangedLogFile.lastModified() < logFile.lastModified()) {
                latestChangedLogFile = logFile;
            }
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(latestChangedLogFile))) {
            String line;
            String lastLine = null;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Scanned IP: ")) {
                    lastLine = line.substring("Scanned IP: ".length()).trim();
                }
            }
            return lastLine;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
