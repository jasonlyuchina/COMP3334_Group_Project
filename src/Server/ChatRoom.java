package Server;

public class ChatRoom {
    private final int session;
    private final ClientHandler client1, client2;


    public ChatRoom(int session, ClientHandler client1, ClientHandler client2) {
        this.session = session;
        this.client1 = client1;
        this.client2 = client2;
    }

    public void start() {
        client1.chat(session);
        client2.chat(session);
        Thread exchangeMessage1 = new Thread(()->{
            while (true) {
                String message = client1.readEncrypted();
                client2.sendEncrypted(message);
            }
        });
        Thread exchangeMessage2 = new Thread(()->{
            while (true) {
                String message = client2.readEncrypted();
                client1.sendEncrypted(message);
            }
        });
        exchangeMessage1.start();
        exchangeMessage2.start();
        while (true) {
            // Listening to exceptions
        }
    }
}
