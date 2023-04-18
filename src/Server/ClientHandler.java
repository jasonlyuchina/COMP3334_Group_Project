package Server;


import Encryption.Encryptions;
import Encryption.UserDatabase;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private final Server server;
    private boolean isAuthenticated;

    private BufferedReader reader;
    private PrintWriter writer;

    private KeyPair RSAKeyPair;
    private PublicKey clientPublicKey;

    private String user;
    private byte[] sharedSecret;

    public ClientHandler(Socket clientSocket, Server server) {
        // Initialization
        this.clientSocket = clientSocket;
        this.server = server;
        isAuthenticated = false;
        // Generate Public Key and Private Key of server side
        generateKeyPair();
    }

    private void establishConnection() {
        try {
            this.reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            this.writer = new PrintWriter(clientSocket.getOutputStream(), true);

        } catch (IOException e) {
            System.err.println("Client connection failed");
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
        KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
        byte[] serverPublicKey = serverKeyPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(serverPublicKey);

        // Send the public key to the client
        writer.println(publicKeyString);

        // Receive the public key from the client
        try {
            String keyString = reader.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            // Convert the byte array to a public key object
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // Generate the shared secret key
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(serverKeyPair.getPrivate());
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
            clientPublicKey = keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            System.err.println("Socket communication error");
        } catch (Exception e) {
            System.err.println("Public Key Decryption error");
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
        // Establish connection between server and client
        establishConnection();
        // Agree on a secret key using DH key exchange
        DHKeyExchange();
        // Send Public Key to client
        sendPublicKey();
        // Receive Public Key from client
        receivePublicKey();

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

