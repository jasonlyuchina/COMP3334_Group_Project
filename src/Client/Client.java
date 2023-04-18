package Client;

import Encryption.Encryptions;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.net.*;

public class Client {
    private String host;
    private int port;
    private Socket clientSocket;

    private BufferedReader reader;
    private PrintWriter writer;

    private KeyPair RSAKeyPair;
    private PublicKey serverPublicKey;
    private byte[] sharedSecret;
    Scanner scanner;


    public Client(String host, int port) {
        this.host = host;
        this.port = port;
        // Generate Public Key and Private Key of client side
        generateKeyPair();
    }

    public void start(int option) {
        // Initialize client socket
        try {
            clientSocket = new Socket(host, port);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Client started on port " + port);
        // Establish connection between server and client
        establishConnection();
        // Agree on a secret key using DH key exchange
        DHKeyExchange();
        // Send Public Key to Server
        sendPublicKey();
        // Receive Public Key from Server
        receivePublicKey();


        if (option == 1) {
            writer.println("register");
            register();
        } else {
            writer.println("login");
            login();
        }

        // After authentication
        scanner = new Scanner(System.in);
        String input = null;
        try {
            input = reader.readLine();
            if (input.equals("Exist")) {
                writer.println("Received");
                joinChatRoom();
            } else if (input.equals("New")) {
                System.out.println("No available waiting rooms");
                createWaitingRoom();
            } else {
                System.err.println("Receive exceptional message: "+input);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Wait for successful creation of chat room
        while (true) {
            try {
                input = reader.readLine();
                if (input == null) {
                    break;
                }
                System.out.println("Received message from server: "+input);
                System.out.println("Chat room created successfully");
                System.out.println("Room id "+input);
                chat();
            } catch (IOException e) {
                System.err.println("Chat room creation error");
                System.exit(1);
            }
        }
    }

    private void joinChatRoom() {
        try {
            // Receive available waiting rooms from server
            String input = reader.readLine();
            // Display available waiting rooms
            System.out.println(input);

            // Prompt for user to select join chat room or create new waiting room
            System.out.println("Input the room number you want to join (-1 to exit): ");


            // Temporarily assume input is valid
            boolean isValid = false;
            while (!isValid) {
                input = scanner.nextLine();
                try {
                    int inputNum = Integer.parseInt(input);
                    writer.println(inputNum);
                    if (inputNum == -1) {
                        createWaitingRoom();
                        /*
                        System.out.println("Do you want to create a new waiting room? (Y/N)");
                        isValid = false;
                        while (!isValid) {
                            input = scanner.nextLine();
                            if (input.equals("Y")) {
                                writer.println(input);
                                isValid = true;
                            } else if (input.equals("N")) {
                                writer.println(input);
                                isValid = true;
                                // To be determined
                            } else {
                                System.out.println("Wrong input! Input Again!");
                            }
                        }
                        */
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Wrong input! Input Again!");
                }
                isValid = true;
            }
            // Successfully join chat room
        } catch (IOException e) {
            System.err.println("Socket communication error");
        }
    }

    private void createWaitingRoom() {
        System.out.println("Do you want to create a new waiting room? (Y/N)");
        boolean isValid = false;
        String input;
        while (!isValid) {
            input = scanner.nextLine();
            if (input.equals("Y")) {
                writer.println(input);
                isValid = true;
                System.out.println("Waiting for other users");
            } else if (input.equals("N")) {
                writer.println(input);
                isValid = true;
                // To be determined
            } else {
                System.out.println("Wrong input! Input Again!");
            }
        }
    }

    private void establishConnection() {
        try {
            this.reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            this.writer = new PrintWriter(clientSocket.getOutputStream(), true);

        } catch (IOException e) {
            System.err.println("Server connection error");
        }
    }

    private void generateKeyPair() {
        try {
            RSAKeyPair = Encryptions.generateRSAKeyPair();
        } catch (Exception e) {
            System.err.println("RSA generation error");
        }
    }

    // Agree on a secret key and send public key encrypted by the secret key
    private void DHKeyExchange() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyPairGenerator.initialize(1024);
        KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
        byte[] clientPublicKey = clientKeyPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(clientPublicKey);

        // Send the public key to the server
        writer.println(publicKeyString);

        // Receive the public key from the server
        try {
            String keyString = reader.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            // Convert the byte array to a public key object
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Generate the shared secret key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(clientKeyPair.getPrivate());
            keyAgreement.doPhase(publicKey, true);
            sharedSecret = keyAgreement.generateSecret();

        } catch (IOException e) {
            System.err.println("Socket communication error");
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private void sendPublicKey() {
        byte[] RSAPublicKey = RSAKeyPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(RSAPublicKey);
        String encryptedRSAPublic = null;
        try {
            encryptedRSAPublic = Encryptions.encrypt(publicKeyString, sharedSecret);
        } catch (Exception e) {
            System.err.println("Public Key encryption error");
        }
        writer.println(encryptedRSAPublic);
    }

    private void receivePublicKey() {
        try {
            String encryptedRSAPublic = reader.readLine();
            String publicKeyString = Encryptions.decrypt(encryptedRSAPublic, sharedSecret);
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
            // Convert the decrypted byte[] to a PublicKey object
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            serverPublicKey = keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            System.err.println("Socket communication error");
        } catch (Exception e) {
            System.err.println("Public Key Decryption error");
        }
    }

    private void register() {
        Scanner scanner = new Scanner(System.in);
        String username, password, email;
        username = null;
        password = null;
        email = null;
        boolean usernameExist = true;

        // Read username and pass to server for verification
        while (usernameExist) {
            System.out.print("Please Input your username: ");
            username = scanner.nextLine();
            try {
                usernameExist = userExist(username);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        // Prompt for strong password
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your password, The password ought to contains Uppercase Character, Lowercase character and digits");
            password=scanner.nextLine();
            try {
                if (!password.matches(".*[A-Z].*")) { // 包含大写字母
                    throw new Exception("Your password must contains uppercase character");
                }
                if (!password.matches(".*[a-z].*")) { // 包含小写字母
                    throw new Exception("Your password must contains lowercase character");
                }
                if (!password.matches(".*\\d.*")) { // 包含数字
                    throw new Exception("Your password must contains digits");
                }
                validInput=true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        // Encrypt password and send to server
        sendEncrypted(password);
        // Read, encrypt email and send to server
        System.out.print("Please Input your email: ");
        email=scanner.nextLine();
        sendEncrypted(email);

        System.out.println("Successful register!");
        //chat();
    }

    private void login() {
        Scanner scanner = new Scanner(System.in);
        String username, password, email, input;
        username = password = email = null;
        boolean usernameExist = false;

        // Read username and pass to server for verification
        while (!usernameExist) {
            System.out.println("Please Input your username");
            username = scanner.nextLine();
            try {
                usernameExist = userExist(username);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        // Receive email to identify server
        email = readEncrypted();
        System.out.println("Is this your Email?,press 1 if it is yours\n"+email);
        input=scanner.nextLine();
        if(!input.equals("1")) {
            System.out.println("Our socket was attacked, you are not connecting the right server");
            System.exit(0);
        }

        // Send password for authentication
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your password");
            password = scanner.nextLine();
            try {
                validInput = passwordMatch(password);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        System.out.println("Successful login!");
        //chat();
    }

    // Return 1 for register, 2 for login, 3 for exit
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

    private boolean userExist(String username) throws IOException {//status =1, then it is login, otherwise, it is register
        sendEncrypted(username);

        String input = null;
        input = reader.readLine();
        if (input == null) {
            throw new NullPointerException();
        }
        return input.equals("Y");
    }

    private void sendEncrypted(String data) {
        String encrypted = null;
        try {
            encrypted = Encryptions.encryptRSA(data, serverPublicKey);
        } catch (Exception e) {
            System.err.println("Message encryption error");
        }
        writer.println(encrypted);
    }

    private String readEncrypted() {
        String decrypted = null;

        try {
            String input = reader.readLine();
            decrypted = Encryptions.decryptRSA(input, RSAKeyPair.getPrivate());
        } catch (IOException e) {
            System.err.println("Socket communication error");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Message decryption error");
        }

        return decrypted;
    }

    private boolean passwordMatch(String password) throws IOException {
        sendEncrypted(password);

        String input = null;
        input = reader.readLine();
        if (input == null) {
            throw new NullPointerException();
        }
        return input.equals("Y");
    }

    public void chat() {
        System.out.println("Chat room created successfully");
        Thread sendingThread = new Thread(new SendingThread(this));
        Thread receivingThread = new Thread(new ReceivingThread(this));
        sendingThread.start();
        receivingThread.start();
    }

    public static void main(String[] args) {
        int option = begin();
        //int port = Integer.parseInt(args[0]);
        int port = 1234;
        Client client = new Client("127.0.0.1", port);
        client.start(option);
    }

    private class SendingThread implements Runnable {
        private Client sender;

        public SendingThread(Client sender) {
            this.sender = sender;
        }

        @Override
        public void run() {
            Scanner scanner = new Scanner(System.in);
            while (true) {
                String message = scanner.nextLine();
                sender.sendEncrypted(message);
            }
        }
    }

    private class ReceivingThread implements Runnable {
        private Client receiver;

        public ReceivingThread(Client receiver) {
            this.receiver = receiver;
        }

        @Override
        public void run() {
            while (true) {
                String message = receiver.readEncrypted();
                System.out.println(message);
            }
        }
    }
}