package Client;

import Encryption.Encryptions;
import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
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

    public Client(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void start(int option) {
        // Initialize client socket
        try {
            clientSocket = new Socket(host, port);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Client started on port " + port);
        // Generate Public Key and Private Key of client side
        generateKeyPair();
        // Send Public Key to Server
        sendPublicKey();
        // Receive Public Key from Server
        receivePublicKey();
        // Establish connection between server and client
        establishConnection();

        if (option == 1) {
            register();
        } else {
            login();
        }

        // After authentication
        try {
            Scanner scanner = new Scanner(System.in);
            String input = reader.readLine();
            boolean isValid = false;
            if (input.equals("Exist")) {
                System.out.println("Input the room number you want to join (-1 to exit): ");
                while (!isValid) {
                    input = scanner.nextLine();
                    try {
                        int inputNum = Integer.parseInt(input);
                        isValid = true;
                        writer.println(inputNum);
                        if (inputNum == -1) {
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
                        }
                    } catch (NumberFormatException e) {
                        System.out.println("Wrong input! Input Again!");
                    }

                    isValid = true;
                }

            } else if (input.equals("New")) {
                System.out.println("Do you want to create a new waiting room? (Y/N)");
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
            }
            // Wait for successful creation of chat room

            while (true) {
                try {
                    input = reader.readLine();
                    if (input == null) {
                        break;
                    }
                    System.out.println("Chat room created successfully");
                    System.out.println("Room id "+input);
                    chat();
                } catch (IOException e) {
                    System.err.println("Chat room creation error");
                    System.exit(1);
                }
            }

        } catch (IOException e) {
            System.err.println("Socket communication error");
        }
    }

    private void generateKeyPair() {
        try {
            RSAKeyPair = Encryptions.generateRSAKeyPair();
        } catch (Exception e) {
            System.err.println("RSA generation error");
        }
    }

    private void sendPublicKey() {
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(RSAKeyPair.getPublic());
            objectOutputStream.flush();
            objectOutputStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void receivePublicKey() {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            try {
                serverPublicKey = (PublicKey)objectInputStream.readObject();
                objectInputStream.close();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
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

    private void register() {
        Scanner scanner = new Scanner(System.in);
        String username, password, email;
        username = password = email = null;
        boolean usernameExist = true;

        // Read username and pass to server for verification
        while (usernameExist) {
            System.out.println("Please Input your username");
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
        email=scanner.nextLine();
        sendEncrypted(email);

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
        int port = Integer.parseInt(args[1]);
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