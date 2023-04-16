package Client;
import Encryption.Encryptions;

import java.io.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;
import java.net.*;
public class Client {
    private String host;
    private int port;
    private Socket clientSocket;

    private BufferedReader reader;
    private PrintWriter writer;

    private KeyPair RSAKeyPair;
    private PublicKey serverPublicKey;

    public Client(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void start(int option) {
        // Initialize client socket
        try {
            clientSocket = new Socket(host, port);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Client started on port " + port);
        // Generate Public Key and Private Key of client side
        generateKeyPair();
        // Send Public Key to Server
        sendPublicKey();
        // Receive Public Key from Server
        receivePublicKey();
        // Establish connection between server and client
        establishConnection();

        if (option == 1) {
            register();
        } else {
            login();
        }
    }

    private void generateKeyPair() {
        try {
            RSAKeyPair = Encryptions.generateRSAKeyPair();
        } catch (Exception e) {
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

    private void receivePublicKey() {
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            try {
                serverPublicKey = (PublicKey)objectInputStream.readObject();
                objectInputStream.close();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
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


    private void register() {
        Scanner scanner = new Scanner(System.in);
        String username, password, email;
        username = password = email = null;
        boolean usernameExist = true;

        // Read username and pass to server for verification
        while (usernameExist) {
            System.out.println("Please Input your username");
            username = scanner.nextLine();
            try {
                usernameExist = userExist(username);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        // Prompt for strong password
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your password, The password ought to contains Uppercase Character, Lowercase character and digits");
            password=scanner.nextLine();
            try {
                if (!password.matches(".*[A-Z].*")) { // 包含大写字母
                    throw new Exception("Your password must contains uppercase character");
                }
                if (!password.matches(".*[a-z].*")) { // 包含小写字母
                    throw new Exception("Your password must contains lowercase character");
                }
                if (!password.matches(".*\\d.*")) { // 包含数字
                    throw new Exception("Your password must contains digits");
                }
                validInput=true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        // Encrypt password and send to server
        sendEncrypted(password);
        // Read, encrypt email and send to server
        email=scanner.nextLine();
        sendEncrypted(email);

        //chat();
    }
    /*
    public static void Register(Socket socket, String myPublicKey, String myPrivateKey,String serverPublicKey) {
        Scanner scanner = new Scanner(System.in);
        String username,password,email;
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your username");
            username=scanner.nextLine();
            try {
                validInput=checkUsername(socket,username,0,serverPublicKey);
            }catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }catch (ServerException e) {
                System.out.println(e.getMessage());
            }
        }
        validInput=false;
        while(!validInput) {
            System.out.println("Please Input your password, The password ought to contains Uppercase Character, Lowercase character and digits");
            password=scanner.nextLine();
            try {
                if (!password.matches(".*[A-Z].*")) { // 包含大写字母
                    throw new Exception("Your password must contains uppercase character");
                }
                if (!password.matches(".*[a-z].*")) { // 包含小写字母
                    throw new Exception("Your password must contains lowercase character");
                }
                if (!password.matches(".*\\d.*")) { // 包含数字
                    throw new Exception("Your password must contains digits");
                }
                validInput=true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        }
        //这里需要把密码上传给系统,用serverpublckey去加密
        email=scanner.nextLine();
        //email上传给系统，用 serverpublickey去加密
        Chat(socket,myPrivateKey,myPublicKey,serverPublicKey);
    }
    */

    private void login() {
        Scanner scanner = new Scanner(System.in);
        String username, password, email, input;
        username = password = email = null;
        boolean usernameExist = false;

        // Read username and pass to server for verification
        while (!usernameExist) {
            System.out.println("Please Input your username");
            username = scanner.nextLine();
            try {
                usernameExist = userExist(username);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        // Receive email to identify server
        email = readEncrypted();
        System.out.println("Is this your Email?,press 1 if it is yours\n"+email);
        input=scanner.nextLine();
        if(!input.equals("1")) {
            System.out.println("Our socket was attacked, you are not connecting the right server");
            System.exit(0);
        }

        // Send password for authentication
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your password");
            password = scanner.nextLine();
            try {
                validInput = passwordMatch(password);
            } catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }
        }

        //chat();
    }
    /*
    public static void Login(Socket socket, String myPublicKey, String myPrivateKey, String serverPublicKey) {
        Scanner scanner = new Scanner(System.in);
        String username,password,email,input;
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your username");
            username=scanner.nextLine();
            try {
                validInput=checkUsername(socket,username,1,serverPublicKey);
            }catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }catch (ServerException e) {
                System.out.println(e.getMessage());
            }
        }
        email="***@***.com";//这里要拿到加密后的email，并且解密 用 myPrivateKey 去解密
        System.out.println("Is this your Email?,press 1 if it is yours\n"+email);
        input=scanner.nextLine();
        if(input!="1") {
            System.out.println("Our socket was attacked, you are not connecting the right server");
            System.exit(0);
        }
        validInput=false;
        while(!validInput) {
            System.out.println("Please Input your password");
            password = scanner.nextLine();
            try {
                validInput = checkPassword(socket, password, serverPublicKey);
            } catch (IOException e) {
                System.out.println("Your socket is stopped");
                System.exit(0);
            } catch (ServerException e) {
                System.out.println(e.getMessage());
            }
        }
        Chat(socket,myPrivateKey,myPublicKey,serverPublicKey);
    }
    */

    // Return 1 for register, 2 for login, 3 for exit
    public static int begin() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to our P2P education Platform!");
        boolean validInput = false;
        int inputNum=0;
        while(!validInput) {
            System.out.println("Press 1 to Register , Press 2 to Log in, Press 0 to Exit");
            String input= scanner.nextLine();
            try {
                inputNum=Integer.parseInt(input);
                if(inputNum < 0 || inputNum > 2) {
                    throw new IllegalArgumentException("Wrong input! Input Again!");
                }
                validInput=true;
            } catch (NumberFormatException e) {
                System.out.println("Wrong input! Input Again!");
            } catch (IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
        }
        if(inputNum==0) {
            System.out.println("Thank you and Goodbye!");
            System.exit(0);
        }
        return inputNum;
    }

    private boolean userExist(String username) throws IOException {//status =1, then it is loggin, otherwise, it is register
        sendEncrypted(username);

        String input = null;
        input = reader.readLine();
        if (input == null) {
            throw new NullPointerException();
        }
        return input.equals("Y");
    }

    private void sendEncrypted(String data) {
        String encrypted = null;
        try {
            encrypted = Encryptions.encryptRSA(data, serverPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        writer.println(encrypted);
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

    private boolean passwordMatch(String password) throws IOException {
        sendEncrypted(password);

        String input = null;
        input = reader.readLine();
        if (input == null) {
            throw new NullPointerException();
        }
        return input.equals("Y");
    }
    /*
    private static boolean checkPassword(Socket socket,String password,String serverPublicKey) throws IOException, ServerException {//status =1, then it is loggin, otherwise, it is register
        boolean isValid = true;
        //这里需要server去check 密码和hash是否相同，用 serverpublickey去加密
        if (!isValid ) {
            // 用户名已存在，抛出自定义异常
            throw new ServerException("Your password is wrong");
        }
        return isValid;
    }
    */

    private void chat() {
    }

    public static void Chat(Socket socket, String myPrivateKey,String myPublicKey, String serverPublicKey) {
        //获取整个用户列表，从socket，服务器传过来，可以不加（optional）
        //向服务器请求要交流的人的port和public key
        //断开之前的socket
        Socket clientSocket=new Socket();//连接另一个client的socket
        String clientPublicKey="fefefef";//获取另一个人的publickey之后加密用
        Scanner scanner= new Scanner(System.in);
        System.out.println("Now you can chat!,If you Input 'Exitn0w', we will end the session!");
        String input="";

        //两个人开始聊天，一个while，发的消息用clientPublicKey加密，收到的东西用myPrivateKey解密
    }

    public static void main(String[] args) {
        int option = begin();

        Client client = new Client("127.0.0.1", 50);
        client.start(option);

        /*
        Socket socket= new Socket();
        String serverPublicKey="dfwerfef";//这个也是需要server回传的
        String myPublicKey="fdassfdsf";
        String myPrivateKey="dsfdfasfdsaf";
        if(option == 1)
            Register(socket,myPublicKey,myPrivateKey,serverPublicKey);
        else Login(socket,myPublicKey,myPrivateKey,serverPublicKey);
         */
    }
}