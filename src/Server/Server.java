package Server;
import Encryption.*;


import java.io.*;
import java.net.*;
import java.util.*;

public class Server {
    private final int port;
    private ServerSocket serverSocket;
    // Clients connected to server with/without authentication
    private List<ClientHandler> clientHandlers;
    // Clients that have already done authentication
    private List<ClientHandler> loggedClients;
    // Available waiting rooms with session number and client waiting
    private Map<Integer, ClientHandler> waitingRooms;
    // Record the session number of waiting room for users to select
    private int waitingRoomNumbers;
    // Formed chat rooms with two clients
    private List<ChatRoom> chatRooms;

    public Server(int port) {
        this.port = port;

        clientHandlers = new ArrayList<>();
        loggedClients = new ArrayList<>();

        waitingRooms = new HashMap<>();
        waitingRoomNumbers = 0;
        chatRooms = new ArrayList<>();
    }

    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);
        } catch (IOException e) {
            System.err.println("Server socket creation error");
            System.exit(1);
        }
        // Connect to database
        /* Implement here */    // Why create connection twice
        SQLiteJDBC.CreateConnection();
        UserDatabase.createTable();

        while (true) {
            // Listen for a connection from the client
            Socket clientSocket = null;
            try {
                clientSocket = serverSocket.accept();
            } catch (IOException e) {
                System.err.println("Client connection error");
            }
            // Record the port number of connected client
            assert clientSocket != null;
            System.out.println("New client connected: " + clientSocket.getInetAddress().getHostAddress());
            // Create a thread to handle client
            ClientHandler clientHandler = new ClientHandler(clientSocket, this);
            clientHandlers.add(clientHandler);
            Thread thread = new Thread(clientHandler);
            thread.start();
        }
    }

    public void addLoggedClient(ClientHandler loggedClient) {
        loggedClients.add(loggedClient);
    }

    public int addWaitingRoom(ClientHandler waitedClient) {
        waitingRoomNumbers++;
        waitingRooms.put(waitingRoomNumbers, waitedClient);
        return waitingRoomNumbers;
    }

    public int getAvailableWaitingRooms() {
        return waitingRooms.size();
    }

    public String displayWaitingRooms() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(String.format("%d waiting room(s) available\n", waitingRooms.size()));
        Set<Integer> keys = waitingRooms.keySet();
        for (int key: keys) {
            stringBuilder.append(String.format("Room id: %d, user: %s\n", key, waitingRooms.get(key).getUser()));
        }
        stringBuilder.append("Input the room number you want to join (-1 to exit): ");
        return stringBuilder.toString();
    }

    public void createChatRoom(int roomNumber, ClientHandler secondClient) {
        ChatRoom chatRoom = new ChatRoom(roomNumber, waitingRooms.get(roomNumber), secondClient);
        chatRooms.add(chatRoom);
        waitingRooms.remove(roomNumber);
        Thread thread = new Thread(chatRoom);
        thread.start();
    }

    public void removeClient(ClientHandler client) {
        clientHandlers.remove(client);
        loggedClients.remove(client);
        client.stop();
    }

    public static void main(String[] args) {
        Server server = new Server(1234);
        server.start();
    }
}
