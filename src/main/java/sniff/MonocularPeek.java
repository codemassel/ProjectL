package sniff;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MonocularPeek {

    public static final String LAST_CHECKED_COORINATE = "CurrentIp.txt";
    public static final String LIST_OF_WEAK_SHIPS = "WeakShips.txt";
    public static long currentIP;
    private final Map<String, Boolean> activeShips = new ConcurrentHashMap<>();
    private List<Thread> scouterList = new ArrayList<Thread>();
    private long startRange;
    private long endrange;
    private int amountOfScouter;
    private Blacklist blacklist = new Blacklist();

    public MonocularPeek(String startRange, String endRange, int amountOfScouter, Blacklist blacklist) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        this.startRange = ipToLong(InetAddress.getByName(startRange));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        this.blacklist = blacklist;
        currentIP = this.startRange;
        recruitScouter(this.amountOfScouter);
    }

    public MonocularPeek(String endRange, int amountOfScouter) throws UnknownHostException {
        createFileIfNotExists(LAST_CHECKED_COORINATE);
        createFileIfNotExists(LIST_OF_WEAK_SHIPS);
        this.startRange = ipToLong(InetAddress.getByName(getCurrentIpFromFile()));
        this.endrange = ipToLong(InetAddress.getByName(endRange));;
        this.amountOfScouter = amountOfScouter;
        currentIP = this.startRange;
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
        if (host.endsWith(".0.0")) {
            System.out.println("Ruffy lets his scouters scan the following coordinates: " + host);
        }
        //System.out.println("Checking ship with " + host + " for weaknesses...");
        blacklist.checkIfEnemyIsOnBlacklist(host, startIp, endIp);

        //TODO: ggf. if-statement auskommentieren und nur scanTelnetPorts ausführen
        scanTelnetPorts(host, 15000);
        /*if (isDeviceReachable(host, 80, 5000)) {
            System.out.println("Found ship: " + host);
            System.out.println("Checking if ship " + host + " is weak enough...");
            scanTelnetPorts(host, 10000);
        //
        }
         */
    }
    private void scanTelnetPorts(String host, int timeout) {
        try {
            if (isPortOpen(host, timeout)) {
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
                System.out.println("Ship: " + host + " is ready to get rämsed");
                System.out.println("-----------------------------------------");
                System.out.println("-----------------------------------------");
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
    /* test method for scouter attacking a ship

        String user = "root";
        String pass = "default";

        try (Socket socket = new Socket(server, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            //send username
            out.println(user);
            out.flush();

            // wait for password request, maybe we need pecific logics here?
            // z.B. "Password: "
            char[] buffer = new char[1024];
            in.read(buffer);

            // send pw
            out.println(pass);
            out.flush();

            // do something with the answer -- atm: print it xd
            in.read(buffer);
            System.out.println(new String(buffer));
     */

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
    //TODO update ip if last_checked_COORDINATE is in blacklist & skip unnecessary blacklisted ips (127.0.0.1 --> 127.255.255.255)
    private void updateIP(String newIP) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LAST_CHECKED_COORINATE))) {
            writer.write(newIP);
        } catch (IOException e) {
            System.out.println("Fehler beim Aktualisieren der Datei " + LAST_CHECKED_COORINATE + ": " + e.getMessage());
        }
    }

    private void addIPAddress(String ipAddress, String response) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LIST_OF_WEAK_SHIPS, true))) {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            writer.write(ipAddress + timestamp + System.lineSeparator() + ", Response: " + response + System.lineSeparator());
            writer.newLine();
            System.out.println("IP-Adresse wurde zur Datei " + LIST_OF_WEAK_SHIPS + " hinzugefügt.");
        } catch (IOException e) {
            System.out.println("Fehler beim Hinzufügen zur Datei " + LIST_OF_WEAK_SHIPS + ": " + e.getMessage());
        }
    }
}
