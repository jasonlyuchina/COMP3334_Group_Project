package Server;

import Encryption.Encryptions;

public class ChatRoom implements Runnable {
    private int session;
    private ClientHandler client1, client2;


    public ChatRoom(int session, ClientHandler client1, ClientHandler client2) {
        this.session = session;
        this.client1 = client1;
        this.client2 = client2;
    }

    @Override
    public void run() {
        client1.chat(session);
        client2.chat(session);
    }
}
