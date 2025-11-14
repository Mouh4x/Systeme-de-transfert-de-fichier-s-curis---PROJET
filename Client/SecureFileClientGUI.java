package Client;

import Securite.CryptoUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class SecureFileClientGUI extends JFrame {

    private JTextField serverIpField;
    private JTextField portField;
    private JTextField loginField;
    private JPasswordField passwordField;
    private JTextField filePathField;
    private JTextArea logArea;

    public SecureFileClientGUI() {
        super("Secure File Client (GUI)");
        initComponents();
    }

    private void initComponents() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        serverIpField = new JTextField("127.0.0.1", 20);
        portField = new JTextField("5000", 6);
        loginField = new JTextField("Norbert", 15);
        passwordField = new JPasswordField("password1", 15);
        filePathField = new JTextField(25);

        int row = 0;
        gbc.gridx = 0; gbc.gridy = row; formPanel.add(new JLabel("Adresse IP serveur:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; formPanel.add(serverIpField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row; formPanel.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; formPanel.add(portField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row; formPanel.add(new JLabel("Login:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; formPanel.add(loginField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row; formPanel.add(new JLabel("Mot de passe:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; formPanel.add(passwordField, gbc);

        row++;
        gbc.gridx = 0; gbc.gridy = row; formPanel.add(new JLabel("Fichier:"), gbc);
        gbc.gridx = 1; gbc.gridy = row; formPanel.add(filePathField, gbc);
        JButton browseButton = new JButton("Parcourir...");
        gbc.gridx = 2; gbc.gridy = row; formPanel.add(browseButton, gbc);

        JButton sendButton = new JButton("Envoyer le fichier");
        gbc.gridx = 1; gbc.gridy = ++row; gbc.gridwidth = 2; formPanel.add(sendButton, gbc);

        mainPanel.add(formPanel, BorderLayout.NORTH);

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        setContentPane(mainPanel);

        browseButton.addActionListener(this::onBrowseFile);
        sendButton.addActionListener(this::onSendFile);
    }

    private void onBrowseFile(ActionEvent e) {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            filePathField.setText(selected.getAbsolutePath());
        }
    }

    private void onSendFile(ActionEvent e) {
        String serverIp = serverIpField.getText().trim();
        String portText = portField.getText().trim();
        String login = loginField.getText().trim();
        String password = new String(passwordField.getPassword());
        String filePath = filePathField.getText().trim();

        if (serverIp.isEmpty() || portText.isEmpty() || login.isEmpty() || password.isEmpty() || filePath.isEmpty()) {
            appendLog("Veuillez remplir tous les champs.");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException ex) {
            appendLog("Port invalide.");
            return;
        }

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            appendLog("Fichier introuvable : " + filePath);
            return;
        }

        new Thread(() -> sendFile(serverIp, port, login, password, file)).start();
    }

    private void sendFile(String serverIp, int port, String login, String password, File file) {
        try {
            byte[] fileBytes = readAllBytes(file);
            String hashHex = CryptoUtils.sha256Hex(fileBytes);

            byte[] encryptedBytes;
            try {
                encryptedBytes = CryptoUtils.encryptAES(fileBytes);
            } catch (Exception e) {
                appendLog("Erreur de chiffrement : " + e.getMessage());
                return;
            }

            try (Socket socket = new Socket(serverIp, port);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream())) {

                appendLog("Connexion au serveur " + serverIp + ":" + port + "...");

                dos.writeUTF(login);
                dos.writeUTF(password);
                dos.flush();

                String authResponse = dis.readUTF();
                if (!"AUTH_OK".equals(authResponse)) {
                    appendLog("Authentification échouée : " + authResponse);
                    return;
                }
                appendLog("Authentification réussie.");

                dos.writeUTF(file.getName());
                dos.writeLong(fileBytes.length);
                dos.writeUTF(hashHex);
                dos.flush();

                String ready = dis.readUTF();
                if (!"READY_FOR_TRANSFER".equals(ready)) {
                    appendLog("Serveur non prêt pour le transfert.");
                    return;
                }
                appendLog("Serveur prêt pour le transfert.");

                dos.writeLong(encryptedBytes.length);
                dos.write(encryptedBytes);
                dos.flush();

                String transferResult = dis.readUTF();
                appendLog("Résultat du transfert : " + transferResult);

            }

        } catch (IOException | NoSuchAlgorithmException ex) {
            appendLog("Erreur : " + ex.getMessage());
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

    private void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            SecureFileClientGUI gui = new SecureFileClientGUI();
            gui.setVisible(true);
        });
    }
}
