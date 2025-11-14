package Serveur;

import Securite.CryptoUtils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class ClientTransferHandler implements Runnable {

    private final Socket clientSocket;

    private static final Map<String, String> USERS = new HashMap<>();

    static {
        USERS.put("Norbert", "password1");
        USERS.put("admin", "admin123");
    }

    public ClientTransferHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try (DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream())) {

            String login = dis.readUTF();
            String password = dis.readUTF();

            if (!authenticate(login, password)) {
                dos.writeUTF("AUTH_FAIL");
                dos.flush();
                return;
            }

            dos.writeUTF("AUTH_OK");
            dos.flush();

            String fileName = dis.readUTF();
            long fileSize = dis.readLong();
            String expectedHash = dis.readUTF();

            System.out.println("Client " + login + " va envoyer le fichier : " + fileName + " (" + fileSize + " bytes)");

            dos.writeUTF("READY_FOR_TRANSFER");
            dos.flush();

            long encryptedSize = dis.readLong();
            byte[] encryptedData = new byte[(int) encryptedSize];
            dis.readFully(encryptedData);

            byte[] decryptedData;
            try {
                decryptedData = CryptoUtils.decryptAES(encryptedData);
            } catch (Exception e) {
                System.err.println("Erreur de déchiffrement : " + e.getMessage());
                dos.writeUTF("TRANSFER_FAIL");
                dos.flush();
                return;
            }

            File receivedDir = new File("received");
            if (!receivedDir.exists()) {
                receivedDir.mkdirs();
            }
            File outputFile = new File(receivedDir, fileName);
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedData);
            }

            boolean ok = verifyIntegrity(decryptedData, expectedHash);

            if (ok) {
                System.out.println("Transfert réussi pour le fichier : " + fileName);
                dos.writeUTF("TRANSFER_SUCCESS");
            } else {
                System.out.println("Échec d'intégrité pour le fichier : " + fileName);
                dos.writeUTF("TRANSFER_FAIL");
            }
            dos.flush();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    private boolean authenticate(String login, String password) {
        String expected = USERS.get(login);
        return expected != null && expected.equals(password);
    }

    private boolean verifyIntegrity(byte[] data, String expectedHash) {
        try {
            String actualHash = CryptoUtils.sha256Hex(data);
            return actualHash.equalsIgnoreCase(expectedHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
    }
}
