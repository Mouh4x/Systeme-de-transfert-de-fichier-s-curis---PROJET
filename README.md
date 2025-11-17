# Système de transfert de fichiers sécurisé (TCP + AES + SHA-256)

Ce projet implémente une application **Client / Serveur** pour le **transfert de fichiers sécurisé** en Java, en utilisant :

- **TCP** pour la communication réseau.
- **AES** (via `javax.crypto`) pour le chiffrement des fichiers.
- **SHA-256** (via `java.security.MessageDigest`) pour l'intégrité.
- Un **protocole de session en 3 phases** (Authentification, Négociation, Transfert).
- Un serveur **multi-threads** (un thread par client).

REALISE PAR : 
- MOUHAMMAD Hassani Hamadi
- DJIGUEMDE Norbert
---

## 1. Arborescence / Structure des fichiers

Dans le dossier ce dossier, le code est structuré en **trois modules** :

- `Serveur/`  
  Contient tout le code côté **serveur** :
  - `Serveur/SecureFileServer.java`  
    Classe principale côté serveur (`package Serveur;`). 
    Écoute sur un port TCP, accepte les connexions et délègue chaque client à un thread `ClientTransferHandler`.
  - `Serveur/ClientTransferHandler.java`  
    Gère une **session complète** avec un client (`package Serveur;`) :
    - Phase 1 : authentification (login / mot de passe).
    - Phase 2 : négociation (nom du fichier, taille, hash SHA-256).
    - Phase 3 : réception des données **chiffrées**, déchiffrement, sauvegarde et vérification d'intégrité.

- `Client/`  
  Contient tout le code côté **client** :
  - `Client/SecureFileClient.java`  
    Client **console** (`package Client;`) :
    - Demande à l'utilisateur : IP du serveur, port, login, mot de passe, chemin du fichier.
    - Lit le fichier, calcule son **SHA-256**, le chiffre avec **AES** (via `CryptoUtils`), puis envoie le tout au serveur.
  - `Client/SecureFileClientGUI.java`  
    Client **graphique** (Swing, `package Client;`) :
    - Interface avec champs IP / Port / Login / Mot de passe.
    - Bouton "Parcourir" pour choisir le fichier.
    - Bouton "Envoyer le fichier".
    - Zone de log affichant les messages (authentification, transfert, succès/échec).

- `Securite/`  
  Contient tout le code de **sécurité** :
  - `Securite/CryptoUtils.java`  
    Utilitaires de sécurité (`package Securite;`) :
    - `encryptAES(byte[] data)` : chiffrement AES (`AES/ECB/PKCS5Padding`).
    - `decryptAES(byte[] encryptedData)` : déchiffrement AES.
    - `sha256Hex(byte[] data)` : calcul du hash SHA-256 et retour en hexadécimal.
    - Clé **AES partagée** entre client et serveur (clé de session simple, stockée en dur).

- Dossier `received/` (créé à l'exécution)  
  Dossier dans lequel le serveur **enregistre les fichiers reçus** (en clair, après déchiffrement) :
  - Exemples : `received/notes.txt`, `received/Carte.jpg`, `received/SAVOIR LIRE LA PRESSE_global.pdf`, etc.

---

## 2. Protocole de communication (3 phases)

### Phase 1 : Authentification

1. Le **client** envoie au serveur (via `DataOutputStream.writeUTF`) :
   - `login`
   - `password`
2. Le **serveur** vérifie les identifiants dans une map :
   - Exemple : `USERS.put("Norbert", "password1");`
3. Le serveur renvoie :
   - `"AUTH_OK"` si les identifiants sont corrects.
   - `"AUTH_FAIL"` sinon, puis ferme la connexion.

### Phase 2 : Négociation

Si l'authentification est OK :

1. Le **client** envoie :
   - Nom du fichier (ex : `notes.txt`).
   - Taille du fichier en octets (avant chiffrement).
   - Hash **SHA-256** du fichier original (hexadécimal).
2. Le **serveur** répond :
   - `"READY_FOR_TRANSFER"` s'il accepte le transfert.

### Phase 3 : Transfert sécurisé et vérification

1. Le **client** :
   - Chiffre le contenu binaire du fichier avec **AES/ECB/PKCS5Padding** (clé partagée).
   - Envoie :
     - La taille des données chiffrées (en octets).
     - Le tableau d'octets chiffré.
2. Le **serveur** :
   - Reçoit les données chiffrées.
   - Les **déchiffre** avec la même clé AES partagée.
   - Sauvegarde le fichier déchiffré sur disque (dossier `received/`).
   - Recalcule le **SHA-256** du contenu reçu et le compare avec le hash attendu.
   - Renvoie au client :
     - `"TRANSFER_SUCCESS"` si les hashes correspondent.
     - `"TRANSFER_FAIL"` sinon.

---

## 3. Sécurité : chiffrement et intégrité

### 3.1 Chiffrement / Déchiffrement (AES)

- Algorithme : **AES** (Advanced Encryption Standard).
- Mode : `AES/ECB/PKCS5Padding` (simple à implémenter, utilisé ici pour le TP).
- Implémentation : via `javax.crypto.Cipher` et `SecretKeySpec`.
- Clé : tableau de 16 octets (AES-128) **partagé** entre client et serveur.

La clé est codée en dur dans `CryptoUtils` :

```java
private static final byte[] SHARED_KEY_BYTES = "MySecretKey12345".getBytes();
```

> Dans un vrai système en production, la clé ne devrait pas être codée en dur, mais **échangée dynamiquement** (RSA, Diffie-Hellman, TLS, etc.).

### 3.2 Intégrité (SHA-256)

- Utilisation de `MessageDigest.getInstance("SHA-256")`.
- Le client calcule le hash SHA-256 du **fichier original** avant chiffrement.
- Le serveur recalcule le SHA-256 sur les données **déchiffrées**.
- Si les deux valeurs sont identiques → intégrité OK.

---

## 4. Lancement et tests (local et distant)

### 4.1 Compilation

Dans le dossier `Examen/` :

```bash
javac Securite/*.java Serveur/*.java Client/*.java
```

(Si aucun message d'erreur n'apparaît, la compilation est réussie.)

### 4.2 Lancer le serveur

Dans un terminal :

```bash
java Serveur.SecureFileServer 5000
```

- Si aucun argument n'est fourni, le serveur utilise par défaut le port 5000.
- Le serveur affiche alors :

```text
SecureFileServer en écoute sur le port 5000...
```

### 4.3 Lancer le client console (sur la même machine)

Dans un autre terminal, dans `Examen/` :

```bash
java Client.SecureFileClient
```

Puis répondre :

- `Adresse IP du serveur (ex: 127.0.0.1)` : `127.0.0.1`
- `Port du serveur (ex: 5000)` : `5000`
- `Login` : `Norbert`
- `Mot de passe` : `password1`
- `Chemin du fichier à envoyer` : chemin complet d'un fichier existant (ex : `C:\Users\Norbert DJIGUEMDE\Desktop\notes.txt`).

### 4.4 Lancer le client graphique (GUI Swing)

Toujours dans `Examen/` :

```bash
java Client.SecureFileClientGUI

```

Une fenêtre s'ouvre avec :

- **Adresse IP serveur** (par défaut `127.0.0.1`).
- **Port** (par défaut `5000`).
- **Login** (par défaut `Norbert`).
- **Mot de passe** (par défaut `password1`).
- Champ **Fichier** + bouton **Parcourir...**.
- Bouton **Envoyer le fichier**.
- Zone de log indiquant les étapes et le résultat (`TRANSFER_SUCCESS` / `TRANSFER_FAIL`).

### 4.5 Test avec un client distant (autre machine)

1. Sur la **machine serveur** :
   - Lancer `ipconfig` et noter l'adresse IPv4 (ex : `172.16.14.2`).
   - Lancer :

     ```bash
     java Serveur.SecureFileServer 5000
     ```

   - Ouvrir le port 5000/TCP dans le **pare-feu Windows** (règle entrante) pour autoriser les connexions depuis le réseau.

2. Sur la **machine cliente distante** :
   - Lancer `SecureFileClient` ou `SecureFileClientGUI`.
   - Dans l'adresse IP serveur, mettre **l'adresse IPv4 de la machine serveur** (ex : `172.16.14.2`).
   - Port : `5000`.
   - Utiliser les identifiants valides (ex : `Norbert` / `password1`).
   - Choisir un fichier local et lancer le transfert.

3. Le fichier reçu sera visible sur la machine serveur dans :

```text
Examen/received/<nom_du_fichier>
```

---

## 5. Pare-feu et sécurité réseau

- Le **pare-feu Windows** bloque par défaut certaines connexions entrantes.
- Pour que les clients distants puissent se connecter au serveur :
  - Autoriser les connexions TCP sur le port **5000**.
  - Soit via l'interface graphique (règle de trafic entrant),
  - Soit via une commande du type :

    ```bash
    netsh advfirewall firewall add rule name="SecureFileServer_5000" dir=in action=allow protocol=TCP localport=5000
    ```

- Il est **préférable** de garder le pare-feu activé et d'ajouter une règle précise plutôt que de le désactiver complètement.

---

## 6. Améliorations possibles

Pour un vrai système en production, on pourrait améliorer :

- **Échange de clé AES sécurisé** :
  - Utiliser RSA ou Diffie-Hellman pour échanger une clé AES de session.
  - Ou utiliser directement **TLS** (HTTPS / SSL) au lieu de gérer la crypto soi-même.

- **Mode de chiffrement** :
  - Remplacer `AES/ECB/PKCS5Padding` par un mode plus sûr comme `AES/CBC/PKCS5Padding` avec IV aléatoire.

- **Gestion des utilisateurs** :
  - Stocker les logins / mots de passe dans un fichier sécurisé ou une base de données.
  - Hacher les mots de passe (ex : bcrypt) au lieu de les stocker en clair.

Ce projet reste volontairement simple pour illustrer :

- Le fonctionnement d'un serveur TCP multi-threads.
- Un protocole de session en plusieurs phases.
- L'utilisation de l'API Java (`javax.crypto`, `MessageDigest`).
- Les problématiques réseau (IP, ports, pare-feu, clients distants).
