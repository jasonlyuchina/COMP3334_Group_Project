package Client;
import java.io.*;
import java.util.Scanner;
import java.net.*;
public class Client {
    public static void main(String[] args) {
        /*使用RSA生成一对Public Key & Private Key
        需要添加的部分
         */
        String myPublicKey="fdassfdsf";
        String myPrivateKey="dsfdfasfdsaf";

        int option= begin();
        /*
        在这里连接一下server的socket
         */
        Socket socket= new Socket();
        String serverPublicKey="dfwerfef";//这个也是需要server回传的
        if(option == 1)
            Register(socket,myPublicKey,myPrivateKey,serverPublicKey);
        else Login(socket,myPublicKey,myPrivateKey,serverPublicKey);
    }
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
    private static boolean checkUsername(Socket socket,String username,int status,String serverPublicKey) throws IOException, ServerException {//status =1, then it is loggin, otherwise, it is register
        boolean isValid = true;
        //这里需要server去check username是否可以用 是不是有重复的用 serverpublickey去加密
        //server那边在注册的时候，要是确定没有的话，就直接存储在SQL里

        if (!isValid ) {
            if(status==0)
                throw new ServerException("There is a same username");
            else throw new ServerException("There is not such a username");
        }
        return isValid;
    }
    private static boolean checkPassword(Socket socket,String password,String serverPublicKey) throws IOException, ServerException {//status =1, then it is loggin, otherwise, it is register
        boolean isValid = true;
        //这里需要server去check 密码和hash是否相同，用 serverpublickey去加密
        if (!isValid ) {
            // 用户名已存在，抛出自定义异常
            throw new ServerException("Your password is wrong");
        }
        return isValid;
    }
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
    }
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


}
