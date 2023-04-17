package Server;


import Encryption.Encryptions;
import Encryption.UserDatabase;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final Server server;
    private boolean isAuthenticated;

    private BufferedReader reader;
    private PrintWriter writer;

    private KeyPair RSAKeyPair;
    private PublicKey clientPublicKey;

    private String user;

    public ClientHandler(Socket clientSocket, Server server) {
        // Initialization
        this.clientSocket = clientSocket;
        this.server = server;
        isAuthenticated = false;
        // Generate Public Key and Private Key of server side
        generateKeyPair();
    }

    private void generateKeyPair() {
        try {
            RSAKeyPair = Encryptions.generateRSAKeyPair();
        } catch (Exception e) {
            System.err.println("RSA generation error");
        }
    }

    // !!! Need modification !!! // Same for client
    // Should not send key directly
    // Instead, we should apply Diffie-Hellman Exchange
    private void receivePublicKey() {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            try {
                clientPublicKey = (PublicKey)objectInputStream.readObject();
                objectInputStream.close();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
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

    private void establishConnection() {
        try {
            this.reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            this.writer = new PrintWriter(clientSocket.getOutputStream(), true);

        } catch (IOException e) {
            System.err.println("Client connection failed");
        }
    }

    private void login() {
        boolean usernameExist;
            // Read username that is not in the DB
            String input, username, password, email;
            username = null;
            do {
                try {
                    input = reader.readLine();
                    if (input == null) {
                        break;
                    }
                    username = Encryptions.decryptRSA(input, RSAKeyPair.getPrivate());
                } catch (IOException e) {
                    System.err.println("Socket communication error");
                } catch (Exception e) {
                    System.err.println("RSA decryption error");
                }

                usernameExist = UserDatabase.userExists(username);
                if (usernameExist) {
                    writer.println("Y");
                } else {
                    writer.println("N");
                }
            } while (!usernameExist);

            // Send email for authentication
            email = UserDatabase.getEmail(username);
            sendEncrypted(email);

            // Read password
            boolean passwordMatch = false;
            while (!passwordMatch) {
                password = readEncrypted();
                passwordMatch = UserDatabase.authenticateUser(username, password);
            }

            setAuthenticated();
            server.addLoggedClient(this);
            user = username;
    }

    private void register() {
        boolean usernameExist;
        // Read username that is not in the DB
        String input, username, password, email;
        username = null;
        do {
            try {
                input = reader.readLine();
                if (input == null) {
                    break;
                }
                username = Encryptions.decryptRSA(input, RSAKeyPair.getPrivate());
            } catch (IOException e) {
                System.err.println("Socket communication error");
            } catch (Exception e) {
                System.err.println("RSA decryption error");
            }

            usernameExist = UserDatabase.userExists(username);
            if (usernameExist) {
                writer.println("Y");
            } else {
                writer.println("N");
            }
        } while (usernameExist);

        // Read password
        password = readEncrypted();

        // Read email
        email = readEncrypted();

        // Store user info
        try {
            UserDatabase.storeUser(username, password, email);
        } catch (Exception e) {
            System.err.println("User information storage error");
        }
        setAuthenticated();
        server.addLoggedClient(this);
        user = username;
    }

    // !!! Need modification !!! //
    public String readEncrypted() {
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

    public void sendEncrypted(String data) {
        String encrypted = null;
        try {
            encrypted = Encryptions.encryptRSA(data, clientPublicKey);
        } catch (Exception e) {
            System.err.println("Message encryption error");
        }
        writer.println(encrypted);
    }

    public String getUser() {
        return user;
    }

    @Override
    public void run() {
        // Receive Public Key from client
        receivePublicKey();
        // Send Public Key to client
        sendPublicKey();
        // Establish connection between server and client
        establishConnection();

        // Client-Server connection
        // User register/login & Authentication
        try {
            while (!isAuthenticated()) {
                String input = reader.readLine();
                if (input == null) {
                    break;
                }
                if (input.equals("login")) {
                    login();
                } else if (input.equals("register")) {
                    register();
                } else {
                    writer.println("Wrong Input");
                }
            }
        } catch (IOException e) {
            System.err.println("Socket communication error");
        }

        // Prompt for input
        // Enter existing waiting room and form a chat room,
        // Or create a new waiting room

        // Display available waiting rooms
        if (server.getAvailableWaitingRooms() > 0) {
            writer.println("Exist");
            String message = server.displayWaitingRooms();
            writer.println(message);
            try {
                String input = reader.readLine();
                int roomNumber = Integer.parseInt(input);
                if (roomNumber != -1) {
                    server.createChatRoom(roomNumber, this);
                }
            } catch (IOException e) {
                System.err.println("Socket communication error");
            }
        }
        writer.println("New");
        try {
            String input = reader.readLine();
            if (input.equals("Y")) {
                int roomNumber = server.addWaitingRoom(this);
                writer.println(roomNumber);
            } else {
                // To be determined
            }
        } catch (IOException e) {
            System.err.println("Socket communication error");
        }
    }

    public void stop() {
    }

    public void chat(int roomNumber) {
        writer.println(roomNumber);
    }

    private void setAuthenticated() {
        isAuthenticated = true;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }
}

