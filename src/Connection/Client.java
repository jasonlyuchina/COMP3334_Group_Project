import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;


public class Client {
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 5000;
    private static int CLIENT_PORT;
    public static int getAvailablePort() {
        int max = 65535;
        int min = 2000;
        Random random = new Random();
        int port = random.nextInt(max) % (max - min + 1) + min;
        boolean using = NetUtils.isLoclePortUsing(port);
        if (using) {
            return getAvailablePort();
        } else {
            return port;
        }
    }
    Client(){
        CLIENT_PORT = getAvailablePort();
    }


    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(CLIENT_PORT);
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            System.out.println("Connected to server: " + SERVER_IP + ":" + SERVER_PORT);

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader serverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            // Start listening for incoming connection requests
            ConnectionListener listener = new ConnectionListener(serverSocket);
            new Thread(listener).start();

            String input;
            while ((input = reader.readLine()) != null) {
                writer.println(input);
                String serverMessage = serverReader.readLine();
                if (serverMessage.startsWith("C-to-C ")) {
                    String[] anotherClient = serverMessage.split(" ");
                    String clientIp = anotherClient[1];
                    int clientPort = Integer.parseInt(anotherClient[2]);

                    Socket clientSocket = new Socket(clientIp, clientPort);
                    System.out.println("Connected to client: " + clientIp + ":" + clientPort);
                    new Thread(new ClientHandler(clientSocket)).start();

                } else {
                    System.out.println("Server says: " + serverMessage);
                }
            }
            socket.close();
        } catch (IOException e) {
            System.out.println("Error connecting to server: " + e);
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
                writer.println("Connected to client " + clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort());
                String input;
                while ((input = reader.readLine()) != null) {
                    System.out.println("Received message from client: " + input);
                }
            } catch (IOException e) {
                System.out.println("Error handling client connection: " + e);
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("Error closing client socket: " + e);
                }
            }
        }
    }

    private static class ConnectionListener implements Runnable {
        private ServerSocket serverSocket;

        public ConnectionListener(ServerSocket serverSocket) {
            this.serverSocket = serverSocket;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    String clientMessage = reader.readLine();
                    if (clientMessage.startsWith("C-to-C ")) {
                        String[] anotherClient = clientMessage.split(" ");
                        String clientIp = anotherClient[1];
                        int clientPort = Integer.parseInt(anotherClient[2]);
                        System.out.println("Received connection response from client: " + clientIp + ":" + clientPort);
                    }
                    clientSocket.close();
                }
            } catch (IOException e) {
                System.out.println("Error accepting client connection: " + e);
            }
        }
    }
}

