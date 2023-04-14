package Server;
import Client.Client;

import java.io.*;
import java.net.*;
import java.util.*;
public class Server {
    /*
    * 1. SQL (Username+Email)
    * 2. Listening to Client
    * 3. Record client name and port number
    * (Optional)
    * 4. Display available connection to users
    */
    private int port;
    private List<ClientHandler> clientHandlers;
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
            /* Implement here */

            while (true) {
                // Listen for a connection from the client
                Socket clientSocket = serverSocket.accept();
                // Record the port number of connected client
                ClientHandler clientHandler = new ClientHandler(clientSocket, this);
                clientHandlers.add(clientHandler);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private class ClientHandler implements Runnable {
        private Socket clientSocket;
        private ServerSocket serverSocket;
        private boolean isAuthenticated;
        private String userName;
        private DataInputStream inputStream;
        private DataOutputStream outputStream;

        public ClientHandler(Socket clientSocket, ServerSocket serverSocket) {
            this.clientSocket = clientSocket;
            this.serverSocket = serverSocket;
            isAuthenticated = false;
            try {
                inputStream = new DataInputStream(clientSocket.getInputStream());
                outputStream = new DataOutputStream(clientSocket.getOutputStream());
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

        public void run() {
            /* Implement here */
        }

        public String getUserName() {
            return userName;
        }

        public boolean isAuthenticated() {
            return isAuthenticated;
        }
    }
}
