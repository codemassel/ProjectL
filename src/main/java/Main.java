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
        String startIp = "103.107.181.36";
        String endIp = "103.255.181.45";
        int numThreads = 2000;

        monocularPeek.discoverShips(startIp, endIp, numThreads);
    }
}