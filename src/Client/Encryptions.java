package Client;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;


public class Encryptions {
    private static final String AES_INIT_VECTOR = "16ByteInitVector";

    private static SecretKey deriveAesKey(byte[] dhSecretKey) throws NoSuchAlgorithmException, InvalidKeyException {

        // Initialize the HKDF with the Diffie-Hellman secret key as the input key material
        Mac hkdf = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(dhSecretKey, "HmacSHA256");
        hkdf.init(keySpec);

        // Extract the key using a salt and an info string
        byte[] salt = new byte[32];
        byte[] info = "AES key derivation".getBytes();
        hkdf.update(salt);
        hkdf.update(info);
        byte[] extractedKey = hkdf.doFinal();

        // Expand the key to the desired length using a different info string
        info = "AES key expansion".getBytes();
        hkdf.update(extractedKey);
        hkdf.update(info);
        byte[] expandedKey = hkdf.doFinal();

        // Wrap the expanded key in a SecretKey object

        return new SecretKeySpec(expandedKey, "AES");
    }

    // Encrypt with the secret key by DH
    public static String encrypt(String data, byte[] secretKey) throws Exception {
        SecretKey secret = deriveAesKey(secretKey);
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt with the secret key by DH
    public static String decrypt(String encryptedData, byte[] secretKey) throws Exception {

        SecretKey secret = deriveAesKey(secretKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(AES_INIT_VECTOR.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, secret, iv);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();
        keyPairGenerator.initialize(2048, random);
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

    // test
    public static void main(String[] args) {
        byte[] byteArray = {-23, 64, 33, 86, 7, 68, -62, 81, -9, -116, 22, 43, -53, 52, 10, 78, 4, -80, -2, -56, 50, -80, -55, 121, -43, 15, -2, -127, -40, -52, 15, 115, 33, -82, 77, -41, -56, -100, -116, -20, -29, 17, 28, -96, 115, 8, 86, 55, -8, -27, 79, 59, 62, -51, -35, 75, 123, -124, -70, -123, -101, 122, -31, -119, 42, -83, 101, -115, -122, -122, -5, -97, -125, -38, 127, -16, -77, 10, 122, -108, -22, 42, 27, 21, 101, -11, 99, -54, -32, 65, 73, 103, 7, -8, -107, -33, -125, -27, 13, 31, -116, -85, 57, 90, -33, -15, 101, 30, -76, 80, -28, -82, -101, -99, -95, -57, 10, -80, -54, 28, -124, -59, -5, 108, 25, -100, -121, -83};

        System.out.println(byteArray.length);
        String message = "Successful!";
        String encrypted=null, decrypted;
        try {
            encrypted = encrypt(message, byteArray);
            System.out.println("Encrypted: "+encrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            decrypted = decrypt(encrypted, byteArray);
            System.out.println("Decrypted: "+decrypted);
        } catch (Exception e) {
            e.printStackTrace();
    }
    }
}
