package sniff;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MonocularPeek {

    private final Map<String, Boolean> activeShips = new ConcurrentHashMap<>();
    private final Map<String, Boolean> telnetShips = new ConcurrentHashMap<>();
    private final Map<String, Boolean> weakShips = new ConcurrentHashMap<>();
    private final Object logFileLock = new Object(); // Lock object for synchronizing log file operations
    private File logFile;

    public MonocularPeek() {
        logFile = findLatestLogFile();
        if (logFile == null) {
            createLogFile();
        }
    }

    private void createLogFile() {
        try {
            String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            String fileName = "PirateAdventures_" + timeStamp + ".txt";
            String directory = "logs";
            File dir = new File(directory);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            logFile = new File(dir, fileName);
            logFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private File findLatestLogFile() {
        File dir = new File("logs");
        if (!dir.exists() || !dir.isDirectory()) {
            return null;
        }

        File[] files = dir.listFiles((d, name) -> name.startsWith("PirateAdventures_") && name.endsWith(".txt"));
        if (files == null || files.length == 0) {
            return null;
        }

        File latestFile = files[0];
        for (File file : files) {
            if (file.lastModified() > latestFile.lastModified()) {
                latestFile = file;
            }
        }

        return latestFile;
    }

    public void discoverShips(String startIp, String endIp) {
        int numThreads = 16;  // Anzahl der Threads (kann an die verfügbare Hardware angepasst werden)
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        try {
            long start = ipToLong(InetAddress.getByName(startIp));
            long end = ipToLong(InetAddress.getByName(endIp));

            for (long ip = start; ip <= end; ip++) {
                final long currentIp = ip;
                executor.submit(() -> {
                    String host = longToIp(currentIp);
                    System.out.println("Checking ship with " + host + " for weaknesses...");

                    try {
                        if (InetAddress.getByName(host).isLoopbackAddress()) {
                            System.out.println("Loopback address, skipping...");
                            return;
                        }
                        if (isDeviceReachable(host, 80, 5000)) { // Port 80 for TCP, timeout of 5 seconds
                            activeShips.put(host, true);
                            System.out.println("Found ship: " + host);
                            System.out.println("Checking if ship " + host + " is weak enough...");
                            scanTelnetPorts(host, 5000); // Timeout of 5 seconds for Telnet port scan
                        }
                        updateLastScannedIp(host);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            }

            executor.shutdown();
            if (!executor.awaitTermination(1, TimeUnit.HOURS)) {
                executor.shutdownNow();
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void scanTelnetPorts(String host, int timeout) {
        try {
            if (!isPortOpen(host, 23, timeout) && !isPortOpen(host, 2323, timeout)) {
                activeShips.remove(host);
                System.out.println("Ship : " + host + " is too strong");
            } else {
                telnetShips.put(host, true);
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                System.out.println("Ship: " + host + " is ready to get rämsed");
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                weakShips.put(host, true);

                // Write the host with open Telnet port to the log file
                writeToLogFile("Ruffy found a weak ship: " + host);
            }
        } catch (Exception e) {
            e.printStackTrace();
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

    public void printResults() {
        System.out.println("Active devices:");
        for (String device : activeShips.keySet()) {
            System.out.println(device);
        }

        System.out.println("Devices with open Telnet ports:");
        for (String device : telnetShips.keySet()) {
            System.out.println(device);
        }
    }

    public Map<String, Boolean> getActiveShips() {
        return activeShips;
    }

    public Map<String, Boolean> getTelnetShips() {
        return telnetShips;
    }

    private void updateLastScannedIp(String ip) {
        synchronized (logFileLock) {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(logFile));
                StringBuilder content = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("Ruffys last checked coordinates:")) {
                        content.append(line).append("\n");
                    }
                }
                reader.close();

                FileWriter writer = new FileWriter(logFile);
                writer.write("Ruffys last checked coordinates: " + ip + "\n" + content);
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void writeToLogFile(String message) {
        synchronized (logFileLock) {
            try (FileWriter writer = new FileWriter(logFile, true)) {
                writer.write(message + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public String getLastScannedIp() {
        if (logFile == null) {
            return null;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Ruffys last checked coordinates:")) {
                    return line.split(": ")[1];
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
