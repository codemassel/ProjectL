import sniff.MonocularPeek;

public class Main {
    // One Piece Episode 1
    public static void main(String[] args) {
        System.out.println("                   |    |    |");
        System.out.println("                  )_)  )_)  )_)");
        System.out.println("                 )___))___))___)");
        System.out.println("                )____)____)_____)");
        System.out.println("             _____|____|____|____\\__");
        System.out.println("    --------- \\                   /---------");
        System.out.println("      ^^^^^ ^^^^^^^^^^^^^^^^^^^^^");
        System.out.println("        ^^^^      ^^^^     ^^^    ^^");
        System.out.println("             ^^^^      ^^^");
        System.out.println("-------------------------------------------------------");
        System.out.println("----------Started to sail hihihihihihihi---------------");
        System.out.println("-------------------------------------------------------");

        // Instantiate ruffy the pirate
        MonocularPeek ruffy = new MonocularPeek();
        // Get the last scanned IP
        String lastScannedIp = ruffy.getLastScannedIp();
        String startIp = (lastScannedIp != null) ? lastScannedIp : "103.107.180.216";

        // Let ruffy scout for enemy ships
        ruffy.discoverShips(startIp, "172.255.255.255");
    }
}