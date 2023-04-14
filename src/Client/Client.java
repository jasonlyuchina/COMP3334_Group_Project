package Client;
import java.io.*;
import java.util.Scanner;
import java.net.*;
public class Client {
    public static void main(String[] args) {
        /*使用RSA生成一对Public Key & Private Key
        public key = ***
        private key = ***
         */
        int option= begin();
        if(option == 1)
            Register();
        else Login();
    }
    public static int begin() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to our P2P education Platform!");
        boolean validInput = false;
        int inputNum=0;
        while(!validInput) {
            System.out.println("Press 1 to Register , Press 2 to Log in, Press 0 to Exit");
            String input= scanner.nextLine();
            try {
                inputNum=Integer.parseInt(input);
                if(inputNum < 0 || inputNum > 2) {
                    throw new IllegalArgumentException("Wrong input! Input Again!");
                }
                validInput=true;
            } catch (NumberFormatException e) {
                System.out.println("Wrong input! Input Again!");
            } catch (IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
        }
        if(inputNum==0) {
            System.out.println("Thank you and Goodbye!");
            System.exit(0);
        }
        return inputNum;
    }
    public static int Register() {
        Scanner scanner = new Scanner(System.in);
        boolean validInput =  false;
        System.out.println("Please Input your username");
        String input = scanner.nextLine();
        try{

        }

    }


}
