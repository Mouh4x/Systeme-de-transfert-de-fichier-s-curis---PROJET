package Serveur;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class SecureFileServer {

    private final int port;

    public SecureFileServer(int port) {
        this.port = port;
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("SecureFileServer en écoute sur le port " + port + "...");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Nouveau client connecté : " + clientSocket.getInetAddress());
                Thread t = new Thread(new ClientTransferHandler(clientSocket));
                t.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        int port = 5000;
        if (args.length >= 1) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.out.println("Port invalide, utilisation du port par défaut 5000.");
            }
        }
        SecureFileServer server = new SecureFileServer(port);
        server.start();
    }
}
