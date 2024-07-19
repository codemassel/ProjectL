import attack.RecruitScouter;
import sniff.MonocularPeek;

import java.net.UnknownHostException;
import java.util.Scanner;

public class Main {
    // One Piece Episode 1
    public static void main(String[] args) throws UnknownHostException {
        printIntro();
        displayMenu();
    }

    private static void printIntro() {
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
        System.out.println("------------Ruffy is on a mission hihihihi-------------");
        System.out.println("-------------------------------------------------------");
    }

    private static void displayMenu() throws UnknownHostException {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\nAuf welche Mission willst du Ruffy schicken?");
            System.out.println("\u0332scannen");
            System.out.println("\u0332recruiten");
            System.out.print("Deine Wahl: ");

            String choice = scanner.nextLine();

            if (choice.equalsIgnoreCase("s")) {
                new MonocularPeek("223.255.255.255", 8000);
                break;
            } else if (choice.equalsIgnoreCase("r")) {
                new RecruitScouter(8000);
                break;
            } else {
                System.out.println("Ungültige Auswahl. Bitte wähle 's' oder 'r'.");
            }
        }
        scanner.close();
    }
}
