package sniff;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MonocularPeek {

    public static final String LAST_CHECKED_COORINATE = "CurrentIp.txt";
    public static final String LIST_OF_WEAK_SHIPS = "WeakShips.txt";
    public static long currentIP;
    private final Map<String, Boolean> ActiveShips = new ConcurrentHashMap<>();
    private List<Thread> scouterList = new ArrayList<Thread>();
    private long StartRange;
    private long endrange;
    private int amountOfScouter;

    public MonocularPeek(String startRange, String endRange, int amountOfScouter) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        this.StartRange = ipToLong(InetAddress.getByName(startRange));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        currentIP = this.StartRange;
        recruitScouter(this.amountOfScouter);
    }

    public MonocularPeek(String endRange, int amountOfScouter) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        this.StartRange = ipToLong(InetAddress.getByName(getCurrentIpFromFile()));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        currentIP = this.StartRange;
        recruitScouter(this.amountOfScouter);
    }

    private void recruitScouter(int counter){
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
        System.out.println("Checking ship with " + host + " for weaknesses...");

        try {
            if (InetAddress.getByName(host).isLoopbackAddress()) {
                System.out.println("Loopback address, skipping...");
                return;
            }
            if (isDeviceReachable(host, 80, 5000)) {
                System.out.println("Found ship: " + host);
                System.out.println("Checking if ship " + host + " is weak enough...");
                scanTelnetPorts(host, 5000);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void scanTelnetPorts(String host, int timeout) {
        try {
            if (!isPortOpen(host, timeout)) {
                ActiveShips.remove(host);
                System.out.println("Ship : " + host + " is too strong");
            } else {
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                System.out.println("Ship: " + host + " is ready to get rämsed");
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                //addIPAddress(host);
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
        if (!isDeviceReachable(host,23, timeout)) {
            return false;
        }

        try (Socket telnetSocket = new Socket()) {
            telnetSocket.connect(new java.net.InetSocketAddress(host, 23), timeout);

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

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }

        return false;
    }

    private long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }

    private String longToIp(long ip) {
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

    public static String getCurrentIpFromFile() {
        File file = new File(LAST_CHECKED_COORINATE);
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String ip = reader.readLine();
                if (ip != null) {
                    System.out.println("Geladene IP-Adresse aus der Datei " + LAST_CHECKED_COORINATE + ": " + ip);
                    return ip;
                } else {
                    System.out.println("Die Datei " + LAST_CHECKED_COORINATE + " ist leer.");
                }
            } catch (IOException e) {
                System.out.println("Fehler beim Lesen der Datei " + LAST_CHECKED_COORINATE + ": " + e.getMessage());
            }
        } else {
            System.out.println("Die Datei " + LAST_CHECKED_COORINATE + " existiert nicht.");
        }
        return null;
    }

    private void updateIP(String newIP) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LAST_CHECKED_COORINATE))) {
            writer.write(newIP);
        } catch (IOException e) {
            System.out.println("Fehler beim Aktualisieren der Datei " + LAST_CHECKED_COORINATE + ": " + e.getMessage());
        }
    }

    // Methode zum Hinzufügen einer neuen IP-Adresse zur Datei
    private void addIPAddress(String ipAddress, String response) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LIST_OF_WEAK_SHIPS, true))) {
            writer.write(ipAddress + ", Response: " + response);
            writer.newLine();
            System.out.println("IP-Adresse wurde zur Datei " + LIST_OF_WEAK_SHIPS + " hinzugefügt.");
        } catch (IOException e) {
            System.out.println("Fehler beim Hinzufügen zur Datei " + LIST_OF_WEAK_SHIPS + ": " + e.getMessage());
        }
    }

}
