package Server;

import java.security.*;
import java.sql.*;

public class UserDatabase{
    private static final String DB_URL = "jdbc:sqlite:user_info.db";

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

    // Test
    public static void main(String[] args) {
        SQLiteJDBC.CreateConnection();
        createTable();

        try {
            storeUser("username2", "password", "email@example.com");
            boolean isAuthenticated = authenticateUser("username", "wrong_pw");
            System.out.println("User authentication result: " + isAuthenticated);
            isAuthenticated = authenticateUser("username2", "password");
            System.out.println("User authentication result: " + isAuthenticated);
            isAuthenticated = authenticateUser("Test1", "Test1234");
            System.out.println("User authentication result: " + isAuthenticated);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
