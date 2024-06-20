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

        MonocularPeek monocularPeek = new MonocularPeek();
        String startIp = "103.107.182.1";
        String endIp = "172.15.255.255";
        int numThreads = 64;

        String lastScannedIp = monocularPeek.getLastScannedIp();
        System.out.println("1. lastscanned "+ lastScannedIp);
        if (lastScannedIp == null) {
            lastScannedIp = startIp;
        }
        System.out.println("Starting discovery from IP: " + lastScannedIp);

        monocularPeek.discoverShips(lastScannedIp, endIp, numThreads);
    }
}