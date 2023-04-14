package Client;
import java.io.*;
import java.util.Scanner;
import java.net.*;
public class Client {
    public static void main(String[] args) {
        /*使用RSA生成一对Public Key & Private Key
        public key = ***
        private key = ***
         */
        int option= begin();
        if(option == 1)
            Register();
        else Login();
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
    private static boolean checkUsername(String username,int status) throws IOException, ServerException {//status =1, then it is loggin, otherwise, it is register
        boolean isValid = true;
        //这里需要server去check username是否可以用 是不是有重复的
        if (!isValid ) {
            // 用户名已存在，抛出自定义异常
            if(status==0)
                throw new ServerException("There is a same username");
            else throw new ServerException("There is not such a username");
        }
        return isValid;
    }
    private static boolean checkPassword(String username) throws IOException, ServerException {//status =1, then it is loggin, otherwise, it is register
        boolean isValid = true;
        //这里需要server去check 密码和hash是否相同
        if (!isValid ) {
            // 用户名已存在，抛出自定义异常
            throw new ServerException("Your password is wrong");
        }
        return isValid;
    }
    public static void Register() {
        Scanner scanner = new Scanner(System.in);
        String username,password,email;
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your username");
            username=scanner.nextLine();
            try {
                validInput=checkUsername(username,0);
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
        //把密码上传给系统
        email=scanner.nextLine();
        //email上传给系统
    }
    public static void Login() {
        Scanner scanner = new Scanner(System.in);
        String username,password,email,input;
        boolean validInput = false;
        while(!validInput) {
            System.out.println("Please Input your username");
            username=scanner.nextLine();
            try {
                validInput=checkUsername(username,1);
            }catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }catch (ServerException e) {
                System.out.println(e.getMessage());
            }
        }
        email="***@***.com";//这里要拿到加密后的email，并且解密
        System.out.println("Is this your Email?,press 1 if it is yours\n"+email);
        input=scanner.nextLine();
        if(input!="1") {
            System.out.println("Our socket was attacked, you are not connecting the right server");
            System.exit(0);
        }
        validInput=false;
        while(!validInput) {
            System.out.println("Please Input your password");
            password=scanner.nextLine();
            try {
                validInput=checkPassword(password);
            }catch (IOException e){
                System.out.println("Your socket is stopped");
                System.exit(0);
            }catch (ServerException e) {
                System.out.println(e.getMessage());
            }
        }




    }


}
