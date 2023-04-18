package Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.Base64;

public class UserDatabase{
    private static final String DB_URL = "jdbc:sqlite:user_info.db";
    private static final String PASSWORD_SALT = "password_salt";
    private static final String AES_SECRET_KEY = "a16ByteSecretKey";
    private static final String AES_INIT_VECTOR = "16ByteInitVector";

    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    public static void createTable(){
        // username password_hash email hash_salt
        try(
                Connection conn = DriverManager.getConnection(DB_URL);
                PreparedStatement stmt = conn.prepareStatement(
                        "CREATE TABLE IF NOT EXISTS users " +
                                "(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_hash TEXT, email TEXT, hash_salt TEXT)")) {
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static String generateRandomSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    public static void storeUser(String username, String password, String email) throws Exception {
        String encryptedUsername = Encryptions.encrypt(username);
        String encryptedEmail = Encryptions.encrypt(email);
        String hashSalt = generateRandomSalt();
        String passwordHash = Encryptions.hash(password, hashSalt);

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(
                     "INSERT INTO users (username, password_hash, hash_salt, email) VALUES (?, ?, ?, ?)")) {
            stmt.setString(1, encryptedUsername);
            stmt.setString(2, passwordHash);
            stmt.setString(3, hashSalt);
            stmt.setString(4, encryptedEmail);
            stmt.executeUpdate();
        }
        System.out.println("User: "+username);
        System.out.println("Password: " +password);
        System.out.println("Email: "+email);
        System.out.println("Encrypted username: "+encryptedUsername);
        System.out.println("Encrypted email: "+encryptedEmail);
        System.out.println("Hash salt: "+hashSalt);
        System.out.println("Hashed password: "+passwordHash);
    }

    public static boolean authenticateUser(String username, String userPassword) {
        // username password_hash email hash_salt
        String query = "SELECT password_hash, hash_salt FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(query)) {

            pstmt.setString(1, Encryptions.encrypt(username));
            ResultSet resultSet = pstmt.executeQuery();

            if (resultSet.next()) {
                String storedPasswordHash = resultSet.getString("password_hash");
                String hashSalt = resultSet.getString("hash_salt");

                //String decryptedPublicKeyB64 = Encryptions.decrypt(encryptedPublicKey, userPassword);
                //byte[] decodedPublicKeyBytes = Base64.getDecoder().decode(decryptedPublicKeyB64);
                //X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKeyBytes);
                //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                //PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

                String userPasswordHash = Encryptions.hash(userPassword, hashSalt);

                return storedPasswordHash.equals(userPasswordHash);
            } else {
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean userExists(String username) {
        String query = "SELECT email FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(query)) {

            pstmt.setString(1, Encryptions.encrypt(username));
            ResultSet resultSet = pstmt.executeQuery();

            return resultSet.next();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String getEmail(String username) {
        String query = "SELECT email FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(query)) {

            pstmt.setString(1, Encryptions.encrypt(username));
            ResultSet resultSet = pstmt.executeQuery();

            if (resultSet.next()) {
                String encrypted_email = resultSet.getString("email");
                return Encryptions.decrypt(encrypted_email);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /*
    public static String encrypt(String data, String password) throws Exception {


        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), PASSWORD_SALT.getBytes(), ITERATIONS, KEY_LENGTH);

        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String encrypt(String data) throws Exception{ // for email
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(AES_SECRET_KEY.toCharArray(), PASSWORD_SALT.getBytes(), ITERATIONS, KEY_LENGTH);

        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }


    public static String decrypt(String encryptedData, String password) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), PASSWORD_SALT.getBytes(), ITERATIONS, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, secret, iv);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static String hash(String data, String hashSalt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(hashSalt.getBytes(StandardCharsets.UTF_8));
        byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static String encryptRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decryptRSA(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
    }
    */


    public static void main(String[] args) {
        SQLiteJDBC.CreateConnection();
        createTable();

        try {
            storeUser("username2", "password", "email@example.com");
            boolean isAuthenticated = authenticateUser("username", "wrong_pw");
            System.out.println("User authentication result: " + isAuthenticated);
            isAuthenticated = authenticateUser("username2", "password");
            System.out.println("User authentication result: " + isAuthenticated);
        } catch (Exception e) {
            e.printStackTrace();
        }

//        try{
//            KeyPair pair = generateRSAKeyPair();
//            PublicKey pk = pair.getPublic();
//            PrivateKey sk = pair.getPrivate();
//            String str = "Hello World";
//            String encrypted = encryptRSA(str, pk);
//            String decrypted = decryptRSA(encrypted, sk);
//            System.out.println("Original: " + str);
//            System.out.println("Encrypted: " + encrypted);
//            System.out.println("Decrypted: " + decrypted);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
    }
}
