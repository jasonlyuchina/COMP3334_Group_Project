import java.io.*;
import java.net.*;
import java.util.*;

public class Server {
    private static final int PORT = 5000;
    private static ArrayList<Socket> clients = new ArrayList<>();



    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server is running...");

        while (true) {
            Socket client = serverSocket.accept();
            clients.add(client);
            System.out.println("New client connected: " + client.getInetAddress().getHostAddress());
            Thread thread = new Thread(new ClientHandler(client));
            thread.start();
        }
    }

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
    public static void sendToAllClients(String message, Socket sender) throws IOException {
        for (Socket client : clients) {
            if (client != sender) {
                sendToClient(message, client, null);
            }
        }
    }

    public static Socket getClient(String ip, int port) {
        for (Socket client : clients) {
            System.out.println(client.getInetAddress().getHostAddress());
            System.out.println(ip);
            System.out.println(client.getPort());
            System.out.println(port);
            if (client.getInetAddress().getHostAddress().equals(ip) && client.getPort() == port) {
                return client;
            }
        }
        return null;
    }

    private static class ClientHandler implements Runnable {
        private Socket client;
        private BufferedReader reader;
        private PrintWriter writer;

        public ClientHandler(Socket client) throws IOException {
            this.client = client;
            this.reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
            this.writer = new PrintWriter(client.getOutputStream(), true);
        }

        @Override
        public void run() {
            try {
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
                            sendToClient(message, targetClient, client);
                        } else {
                            writer.println("Client not found");
                        }
                    } else {
                        sendToAllClients(input, client);
                    }
                }
            } catch (IOException e) {
                System.out.println("Error handling client: " + e);
            } finally {
                try {
                    client.close();
                    clients.remove(client);
                } catch (IOException e) {
                    System.out.println("Error closing client: " + e);
                }
                System.out.println("Client disconnected: " + client.getInetAddress().getHostAddress());
            }
        }
    }
}
