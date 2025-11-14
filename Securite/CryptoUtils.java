package Securite;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CryptoUtils {

    private static final byte[] SHARED_KEY_BYTES = "MySecretKey12345".getBytes();

    private static SecretKeySpec getSecretKey() {
        return new SecretKeySpec(SHARED_KEY_BYTES, "AES");
    }

    public static byte[] encryptAES(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey());
        return cipher.doFinal(encryptedData);
    }

    public static String sha256Hex(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
