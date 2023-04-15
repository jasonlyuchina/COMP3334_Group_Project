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
        String encryptedUsername = encrypt(username);
        String encryptedEmail = encrypt(email);
        String hashSalt = generateRandomSalt();
        String passwordHash = hash(password, hashSalt);

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(
                     "INSERT INTO users (username, password_hash, hash_salt, email) VALUES (?, ?, ?, ?)")) {
            stmt.setString(1, encryptedUsername);
            stmt.setString(2, passwordHash);
            stmt.setString(3, hashSalt);
            stmt.setString(4, encryptedEmail);
            stmt.executeUpdate();
        }
    }

    private static boolean authenticateUser(String username, String inputPassword) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(
                     "SELECT password_hash, hash_salt FROM users WHERE username = ?")) {
            stmt.setString(1, encrypt(username));
            ResultSet resultSet = stmt.executeQuery();

            if (resultSet.next()) {
                String storedPasswordHash = resultSet.getString("password_hash");
                String hashSalt = resultSet.getString("hash_salt");
                String inputPasswordHash = hash(inputPassword, hashSalt);
                if (storedPasswordHash.equals(inputPasswordHash)) {
                    return true;
                } else {
                    System.out.println("Password is incorrect.");
                    return false;
                }
            } else {
                System.out.println("Username not found.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    private static String encrypt(String data) throws Exception {

        // Generate SecretKeyFactory instance based on PBKDF2 key derivation function.
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        // Generate PBEKeySpec instance based on password and salt, transforming AES_SECRET_KEY into a byte array.
        KeySpec spec = new PBEKeySpec(AES_SECRET_KEY.toCharArray(), PASSWORD_SALT.getBytes(), ITERATIONS, KEY_LENGTH);

        // Generate SecretKey instance based on PBEKeySpec instance.
        SecretKey tmp = factory.generateSecret(spec);

        // Convert the SecretKey instance into a SecretKeySpec instance, which is suitable for AES encryption.
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));

        // Generate Cipher instance based on AES encryption.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Initialize the Cipher instance with the SecretKeySpec instance.
        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);

        // Encrypt the data.
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Return the encrypted data as a Base64 encoded string.
        return Base64.getEncoder().encodeToString(encrypted);
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

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) {
        createTable();
        try {
            storeUser("username2", "password", "email@example.com");
            boolean isAuthenticated = authenticateUser("username", "wrong_pw");
            System.out.println("User authentication result: " + isAuthenticated);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}