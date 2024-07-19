package sniff;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class MonocularPeek {

    public final String LAST_CHECKED_COORDINATE = "CurrentIp.txt";
    public final String LIST_OF_WEAK_SHIPS = "WeakShips.txt";
    private static final String LIST_OF_RECRUITMENTS = "Recruits.txt";
    public long currentIP;
    private final List<Thread> scouterList = new ArrayList<Thread>();
    private final long startRange;
    private final long endrange;
    private final int amountOfScouter;
    private Blacklist blacklist = new Blacklist();
    private final String ANSI_GREEN = "\u001B[32m";
    private final String ANSI_RESET = "\u001B[0m";

    public MonocularPeek(String startRange, String endRange, int amountOfScouter, Blacklist blacklist) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORDINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        createFileIfNotExists(LIST_OF_RECRUITMENTS);
        this.startRange = ipToLong(InetAddress.getByName(startRange));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        this.blacklist = blacklist;
        currentIP = this.startRange;
        findScouter(this.amountOfScouter);
    }

    public MonocularPeek(String endRange, int amountOfScouter) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORDINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        createFileIfNotExists(LIST_OF_RECRUITMENTS);
        this.startRange = ipToLong(InetAddress.getByName(getCurrentIpFromFile()));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        currentIP = this.startRange;
        findScouter(this.amountOfScouter);
    }

    private void findScouter(int counter){
        for(int i = 0; i < counter; i++) {
            int threadNumber = i;
            scouterList.add(new Thread() {
                public void run() {
                    long currentLocalIp = currentIP + threadNumber;
                    while(true) {
                        discoverShips(currentLocalIp, endrange);
                        updateIP(longToIp(currentLocalIp));
                        currentLocalIp += amountOfScouter;
                    }
                }
            });
        }
        startScouting();
    }

    private void startScouting(){
        for(Thread scouter : scouterList){
            scouter.start();
        }
    }

    private void discoverShips(long startIp, long endIp) {
        String host = longToIp(startIp);
        if (host.endsWith(".0.0")) {
            System.out.println(ANSI_GREEN + "Ruffy lets his scouters scan the following coordinates: " + host + ANSI_RESET);
        }
        System.out.println("Checking ship with " + host + " for weaknesses...");
        blacklist.checkIfEnemyIsOnBlacklist(host, startIp, endIp);
        scanTelnetPorts(host, 15000);
    }
    private void scanTelnetPorts(String host, int timeout) {
        try {
            if (isPortOpen(host, timeout)) {
                System.out.println(ANSI_GREEN +"-----------------------------------------"+ ANSI_RESET);
                System.out.println(ANSI_GREEN +"-----------------------------------------"+ ANSI_RESET);
                System.out.println(ANSI_GREEN +"Ship: " + host + " is ready to get rämsed"+ ANSI_RESET);
                System.out.println(ANSI_GREEN +"-----------------------------------------"+ ANSI_RESET);
                System.out.println(ANSI_GREEN +"-----------------------------------------"+ ANSI_RESET);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean isDeviceReachable(String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public boolean isPortOpen(String host, int timeout) {
        /*if (!isDeviceReachable(host,23, timeout/2)) {
            return false;
        }

         */

        try (Socket telnetSocket = new Socket()) {
            telnetSocket.connect(new java.net.InetSocketAddress(host, 23), timeout);

            if (telnetSocket.isConnected()) {
                OutputStream out = telnetSocket.getOutputStream();
                InputStream in = telnetSocket.getInputStream();

                out.write("hello\n".getBytes());
                out.flush();

                Thread.sleep(timeout);

                if (in.available() > 0) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = in.read(buffer);
                    if (bytesRead > 0) {
                        String response = new String(buffer, 0, bytesRead);
                        System.out.println("Received: " + response);
                        addIPAddress(host, response);
                        return true;
                    }
                }
            }

        } catch (IOException | InterruptedException e) {
            if (e instanceof java.net.SocketTimeoutException) {
                //silently handle sockettimeout
            } else {
                e.printStackTrace();
            }
            return false;
        }
        return false;
    }
    protected long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }

    protected String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    private void createFileIfNotExists(String fileName) {
        File file = new File(fileName);
        if (!file.exists()) {
            try {
                file.createNewFile();
                System.out.println("Die Datei " + fileName + " wurde erstellt.");
            } catch (IOException e) {
                System.out.println("Fehler beim Erstellen der Datei " + fileName + ": " + e.getMessage());
            }
        } else {
            System.out.println("Die Datei " + fileName + " existiert bereits.");
        }
    }

    public String getCurrentIpFromFile() {
        File file = new File(LAST_CHECKED_COORDINATE);
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String ip = reader.readLine();
                if (ip != null) {
                    System.out.println("Geladene IP-Adresse aus der Datei " + LAST_CHECKED_COORDINATE + ": " + ip);
                    return ip;
                } else {
                    System.out.println("Die Datei " + LAST_CHECKED_COORDINATE + " ist leer.");
                }
            } catch (IOException e) {
                System.out.println("Fehler beim Lesen der Datei " + LAST_CHECKED_COORDINATE + ": " + e.getMessage());
            }
        } else {
            System.out.println("Die Datei " + LAST_CHECKED_COORDINATE + " existiert nicht.");
        }
        return null;
    }
    //TODO update ip if last_checked_COORDINATE is in blacklist & skip unnecessary blacklisted ips (127.0.0.1 --> 127.255.255.255)
    private void updateIP(String newIP) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LAST_CHECKED_COORDINATE))) {
            writer.write(newIP);
        } catch (IOException e) {
            System.out.println("Fehler beim Aktualisieren der Datei " + LAST_CHECKED_COORDINATE + ": " + e.getMessage());
        }
    }

    private void addIPAddress(String ipAddress, String response) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LIST_OF_WEAK_SHIPS, true))) {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            writer.write(ipAddress +" " + timestamp + System.lineSeparator() + ", Response: " + response + System.lineSeparator());
            writer.newLine();
            System.out.println("IP-Adresse wurde zur Datei " + LIST_OF_WEAK_SHIPS + " hinzugefügt.");
        } catch (IOException e) {
            System.out.println("Fehler beim Hinzufügen zur Datei " + LIST_OF_WEAK_SHIPS + ": " + e.getMessage());
        }
    }
    public static String getLIST_OF_RECRUITMENTS() {
        return LIST_OF_RECRUITMENTS;
    }
}
