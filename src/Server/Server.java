package Server;
import Client.Client;
import Encryption.*;


import java.io.*;
import java.net.*;
import java.util.*;
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

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private Server server;
        private boolean isAuthenticated;
        private String userName;
        //private DataInputStream inputStream;
        //private DataOutputStream outputStream;
        private BufferedReader reader;
        private PrintWriter writer;

        public ClientHandler(Socket clientSocket, Server server) {
            this.clientSocket = clientSocket;
            this.server = server;
            isAuthenticated = false;
            try {
                //inputStream = new DataInputStream(clientSocket.getInputStream());
                //outputStream = new DataOutputStream(clientSocket.getOutputStream());
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

        private void Login() {
            try {
                while (!isAuthenticated) {
                    // Receive Username + Password encrypted by Public Key
                    // Format: "Alice" "23asd8891"
                    String input = reader.readLine();
                    String[] tokens = input.split(" ");
                    // Suppose we already have public key transferred from the user
                    String publicKey = "Public Key";
                    String password = UserDatabase.decrypt(tokens[1], publicKey);



                }


                while (!isAuthenticated) {
                    // Receive Username + Public Key encrypted by password
                    String input = reader.readLine();
                    String[] tokens = input.split(" ");
                    if (UserDatabase.authenticateUser(tokens[0], tokens[1])) {
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
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void run() {
            try {
                // Client-Server connection
                // User register/login & Authentication
                /* Implement here */
                String input = reader.readLine();
                boolean login = false;
                boolean register = false;
                if (login) {

                }

                if (register) {
                    input = reader.readLine();
                    String[] tokens = input.split(" ");
                    try {
                        // format: Tag username password e-mail
                        UserDatabase.storeUser(tokens[1], tokens[2], tokens[3]);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                // After authentication
                while (true) {
                    input = reader.readLine();
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
        }

        public void parse(String input, String username, String password) {

        }

        public Socket getSocket() {
            return clientSocket;
        }

        public String getUserName() {
            return userName;
        }

        public boolean isAuthenticated() {
            return isAuthenticated;
        }
    }
}
