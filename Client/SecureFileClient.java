package Client;

import Securite.CryptoUtils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class SecureFileClient {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Adresse IP du serveur (ex: 127.0.0.1) : ");
        String serverIp = scanner.nextLine().trim();

        System.out.print("Port du serveur (ex: 5000) : ");
        int port = Integer.parseInt(scanner.nextLine().trim());

        System.out.print("Login : ");
        String login = scanner.nextLine().trim();

        System.out.print("Mot de passe : ");
        String password = scanner.nextLine().trim();

        System.out.print("Chemin du fichier à envoyer : ");
        String filePath = scanner.nextLine().trim();

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("Fichier introuvable : " + filePath);
            return;
        }

        try {
            byte[] fileBytes = readAllBytes(file);
            String hashHex = CryptoUtils.sha256Hex(fileBytes);

            byte[] encryptedBytes;
            try {
                encryptedBytes = CryptoUtils.encryptAES(fileBytes);
            } catch (Exception e) {
                System.err.println("Erreur de chiffrement : " + e.getMessage());
                return;
            }

            try (Socket socket = new Socket(serverIp, port);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream())) {

                dos.writeUTF(login);
                dos.writeUTF(password);
                dos.flush();

                String authResponse = dis.readUTF();
                if (!"AUTH_OK".equals(authResponse)) {
                    System.out.println("Authentification échouée : " + authResponse);
                    return;
                }
                System.out.println("Authentification réussie.");

                dos.writeUTF(file.getName());
                dos.writeLong(fileBytes.length);
                dos.writeUTF(hashHex);
                dos.flush();

                String ready = dis.readUTF();
                if (!"READY_FOR_TRANSFER".equals(ready)) {
                    System.out.println("Serveur non prêt pour le transfert.");
                    return;
                }
                System.out.println("Serveur prêt pour le transfert.");

                dos.writeLong(encryptedBytes.length);
                dos.write(encryptedBytes);
                dos.flush();

                String transferResult = dis.readUTF();
                System.out.println("Résultat du transfert : " + transferResult);

            }

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static byte[] readAllBytes(File file) throws IOException {
        long length = file.length();
        if (length > Integer.MAX_VALUE) {
            throw new IOException("Fichier trop volumineux.");
        }
        byte[] data = new byte[(int) length];
        try (FileInputStream fis = new FileInputStream(file)) {
            int offset = 0;
            int bytesRead;
            while (offset < data.length && (bytesRead = fis.read(data, offset, data.length - offset)) != -1) {
                offset += bytesRead;
            }
            if (offset < data.length) {
                throw new IOException("Impossible de lire tout le fichier.");
            }
        }
        return data;
    }
}
