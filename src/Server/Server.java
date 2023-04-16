package Server;
import Client.Client;
import Encryption.*;


import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.security.KeyPair;
import java.util.logging.SocketHandler;

public class Server {
    /*
    * 1. SQL (Username+Email)
    * 2. Listening to Client
    * 3. Record client name and port number
    * (Optional)
    * 4. Display available connection to users
    */
    private int port;
    private static List<ClientHandler> clientHandlers;
    private Map<String, ClientHandler> connectedClients;
    private ServerSocket serverSocket;

    public Server(int port) {
        this.port = port;
        clientHandlers = new ArrayList<>();
        connectedClients = new HashMap<>();
    }

    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);

            // Connect to database
            /* Implement here */    // Why create connection twice
            SQLiteJDBC.CreateConnection();
            UserDatabase.createTable();

            while (true) {
                // Listen for a connection from the client
                Socket clientSocket = serverSocket.accept();
                // Record the port number of connected client
                System.out.println("New client connected: " + clientSocket.getInetAddress().getHostAddress());
                ClientHandler clientHandler = new ClientHandler(clientSocket, this);
                clientHandlers.add(clientHandler);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Client to Client communication
    /*
    // To be modified
    public static void sendToClient(String message, Socket targetClient, Socket Client) throws IOException {
        if (Client != null) {
            PrintWriter clientWriter = new PrintWriter(Client.getOutputStream(), true);
            String msg = "C-to-C " + targetClient.getInetAddress().getHostAddress() + " " + targetClient.getPort() + " " + message;
            clientWriter.println(msg);
        } else {
            PrintWriter targetWriter = new PrintWriter(targetClient.getOutputStream(), true);
            System.out.println("newmsg: " + message);
            targetWriter.println(message);
            targetWriter.flush();
        }
    }

    // To be modified
    public static void sendToAllClients(String message, Socket sender) throws IOException {
        for (ClientHandler clientHandler : clientHandlers) {
            Socket clientSocket = clientHandler.getSocket();
            if (clientSocket.equals(sender)) {
                sendToClient(message, clientSocket, null);
            }
        }
    }

    // To be modified
    public static Socket getClient(String ip, int port) {
        for (ClientHandler clientHandler : clientHandlers) {
            Socket clientSocket = clientHandler.getSocket();
            System.out.println(clientSocket.getInetAddress().getHostAddress());
            System.out.println(ip);
            System.out.println(clientSocket.getPort());
            System.out.println(port);
            if (clientSocket.getInetAddress().getHostAddress().equals(ip) && clientSocket.getPort() == port) {
                return clientSocket;
            }
        }
        return null;
    }

    public void removeClient(ClientHandler clientHandler) {
        clientHandlers.remove(clientHandler);
    }
    */

    private static class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final Server server;
        private boolean isAuthenticated;

        private BufferedReader reader;
        private PrintWriter writer;

        private KeyPair RSAKeyPair;
        private PublicKey clientPublicKey;

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
                e.printStackTrace();
            }
        }

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
                e.printStackTrace();
            }
        }

        /* Procedure
        * 1. Establish channel between server and client
        * 2. User login/register
        * 3. Authenticate user recursively until verified
        * 4. Add to loggedClients
        * 5. Maintain connection
        * (Optional)
        * 6. Display other online users
        * 7. Prompt users to select other user for communication
        * (Mandatory)
        * 8. Establish channel between clients
        * 9. Disable connection of server
        */

        private void login() {
            boolean usernameExist = false;
            try {
                // Read username that is not in the DB
                String input, username, password, email;
                username = password = email = null;
                do {
                    input = reader.readLine();
                    try {
                        username = Encryptions.decryptRSA(input, RSAKeyPair.getPrivate());
                    } catch (Exception e) {
                        e.printStackTrace();
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

                // Should handle exceptions if client disconnects
                /* Implement here */

                // Read password
                boolean passwordMatch = false;
                while (!passwordMatch) {
                    password = readEncrypted();
                    passwordMatch = UserDatabase.authenticateUser(username, password);
                }

                setAuthenticated();
            } catch (IOException e) {
                e.printStackTrace();
            }

            /*
            while (!isAuthenticated()) {
                try {
                    // Receive Username + Password encrypted by Public Key of server
                    // Format: "Alice" "9471985913"
                    String input = reader.readLine();
                    String[] tokens = input.split(" ");

                    // Suppose we already have public key transferred to the user
                    String password = Encryptions.decryptRSA(tokens[1], RSAKeyPair.getPrivate());
                    if (UserDatabase.authenticateUser(tokens[0], password)) {
                        // Successful Login
                    } else {
                        // Wrong password or Username does not exist (should be handled in advance)
                    }
                    // Send e-mail address to client encrypted by Public Key of client
                    // Receive Public Key of client

                /*
                // Receive Username + Public Key encrypted by password
                input = reader.readLine();
                tokens = input.split(" ");
                if (Encryptions.authenticateUser(tokens[0], tokens[1])) {
                    // Decrypt Public Key with password
                    String publicKey = "Public Key";
                    // Generate random key K
                    String k = "Random Key";
                    // Encrypt K with Public Key
                    String encryptedK_PK = "Encrypt k with Public Key";
                    // Encrypt again with password
                    String encryptedK_pwd = "Encrypt again with password";
                    // Send to client
                    sendToClient(encryptedK_pwd, clientSocket, null);
                    // Receive challenge encrypted by K
                    input = reader.readLine();
                    tokens = input.split(" ");
                    // Decrypt with K and get challenge
                    String challenge = "challenge";
                    // Encrypt challenge and email(Response) with K
                    String encryptedResponse = "encrypt response with K";
                    sendToClient(encryptedResponse, clientSocket, null);
                }


                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            */
        }

        private void register() {
            boolean usernameExist = true;
            try {
                // Read username that is not in the DB
                String input, username, password, email;
                username = password = email = null;
                do {
                    input = reader.readLine();
                    try {
                        username = Encryptions.decryptRSA(input, RSAKeyPair.getPrivate());
                    } catch (Exception e) {
                        e.printStackTrace();
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
                    e.printStackTrace();
                }
                setAuthenticated();
            } catch (IOException e) {
                e.printStackTrace();
            }
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
                e.printStackTrace();
            }

            return decrypted;
        }

        private void sendEncrypted(String data) {
            String encrypted = null;
            try {
                encrypted = Encryptions.encryptRSA(data, clientPublicKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            writer.println(encrypted);
        }

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
                    if (input.equals("login")) {
                        login();
                    } else if (input.equals("register")) {
                        register();
                    } else {
                        System.out.println("Wrong Input");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            /*
            // Client-Client connection
            try {
                // After authentication
                while (true) {
                    String input = reader.readLine();
                    if (input == null) {
                        break;
                    }

                    if (input.startsWith("/msg")) { // client-to-client connection
                        // format for the client-to-client request: "/msg 192.168.0.2 5001 Hello there!"
                        String[] tokens = input.split(" ");
                        String targetIp = tokens[1];
                        int targetPort = Integer.parseInt(tokens[2]);
                        Socket targetClient = getClient(targetIp, targetPort);
                        if (targetClient != null) {
                            String message = tokens[3];
                            sendToClient(message, targetClient, clientSocket);
                        } else {
                            writer.println("Client not found");
                        }
                    } else {
                        sendToAllClients(input, clientSocket);
                    }
                }
            } catch (IOException e) {
                System.out.println("Error handling client: " + e);
            } finally {
                try {
                    clientSocket.close();
                    server.removeClient(this);
                } catch (IOException e) {
                    System.out.println("Error closing client: " + e);
                }
                System.out.println("Client disconnected: " + clientSocket.getInetAddress().getHostAddress());
            }
            */
        }

        public Socket getSocket() {
            return clientSocket;
        }

        private void setAuthenticated() {
            isAuthenticated = true;
        }

        public boolean isAuthenticated() {
            return isAuthenticated;
        }
    }

    public static void main(String[] args) {
        Server server = new Server(1234);
        server.start();
    }
}
