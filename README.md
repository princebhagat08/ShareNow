# Secure P2P File Sharing Application

A real-time, peer-to-peer file sharing application featuring **End-to-End Encryption** (E2EE) using  AES-256-GCM and secure Diffie-Hellman key exchange.

![Project Banner](https://img.shields.io/badge/Security-AES--256--GCM-green)
![Python](https://img.shields.io/badge/Backend-Python%20Flask-blue)
![SocketIO](https://img.shields.io/badge/Realtime-Socket.IO-orange)

## 🚀 Step-by-Step Working

### 1. Peer Discovery & Connection
1. **Open the App**: Two users open the application on their browsers.
2. **Select Roles**:
   - User A selects **"Sender"** and enters their name (e.g., "Alice").
   - User B selects **"Receiver"** and enters their name (e.g., "Bob").
3. **Auto-Discovery**: The application uses WebSockets to automatically detect other users on the network.
   - Alice sees Bob in her "Available Peers" list.
4. **Connect**:
   - Alice clicks **"Connect"** next to Bob's name.
   - Bob receives a popup request and clicks **"Accept"**.
   - A secure WebSocket room is established between them.

### 2. Secure Key Exchange (The Handshake)
Once connected, the app automatically performs a **Diffie-Hellman Key Exchange** in the background.

1. **Key Generation**:
   - Alice generates a private key ($a$) and public key ($A = g^a \mod p$).
   - Bob generates a private key ($b$) and public key ($B = g^b \mod p$).
2. **Exchange**:
   - Alice sends her public key ($A$) to Bob.
   - Bob sends his public key ($B$) to Alice.
   *Note: Private keys never leave the user's device.*
3. **Secret Derivation**:
   - Alice computes $S = B^a \mod p$.
   - Bob computes $S = A^b \mod p$.
   - Both now have the **same shared secret** ($S$) without ever transmitting it.
4. **HKDF**: The shared secret is passed through a Key Derivation Function (HKDF-SHA256) to generate a strong **256-bit AES Key**.

### 3. File Encryption (Sender Side)
When Alice selects a file and clicks "Send":

1. **File Reading**: The file is read as binary data (bytes).
2. **IV Generation**: A unique, random 12-byte **Initialization Vector (IV)** is generated.
3. **Encryption (AES-256-GCM)**:
   - The file data + the derived 256-bit Key + the IV are fed into the AES-GCM algorithm.
   - **Output**: `Ciphertext` (encrypted data) + `Auth Tag` (proof of integrity).
4. **Packaging**: The app packages `IV + Auth Tag + Ciphertext` into a single blob.
5. **Transmission**: This encrypted blob is sent over WebSocket to Bob.

### 4. File Decryption (Receiver Side)
When Bob receives the data:

1. **Unpacking**: The app separates the `IV`, `Auth Tag`, and `Ciphertext`.
2. **Decryption (AES-256-GCM)**:
   - Bob's browser uses the same **Shared Secret Key**, the received `IV`, and the `Auth Tag`.
   - The algorithm verifies integrity (ensuring no tampering) and decrypts the `Ciphertext`.
3. **Output**: The original file bytes are recovered.
4. **Download**: The browser instantly triggers a download of the decrypted file.

---

## 🔐 Technical Deep Dive

### 1. Diffie-Hellman Key Exchange (The "Magic")
How can two people agree on a secret password over a public room without anyone else knowing it?

- **Analogy**:
    - Alice and Bob agree on a common paint color (Yellow).
    - Alice picks a secret color (Red) and mixes it with Yellow → Orange. She sends Orange to Bob.
    - Bob picks a secret color (Blue) and mixes it with Yellow → Green. He sends Green to Alice.
    - **The Trick**:
        - Alice takes Bob's Green + adds her Red → Brown.
        - Bob takes Alice's Orange + adds his Blue → Brown.
    - Result: Both have the **same final color (Brown)**, but an eavesdropper only saw Orange and Green and can't un-mix them to find the secret Red or Blue.

- **In Code (`crypto_engine.py`)**:
    We use the **RFC 3526 2048-bit MODP Group**, which is a standard, secure set of numbers for this math.

### 2. AES-256-GCM (The "Vault")
- **AES (Advanced Encryption Standard)**: The standard used by governments and banks. "256" means the key is 256 bits long (extremely hard to brute force).
- **GCM (Galois/Counter Mode)**: This is a modern "mode" of AES that provides two things:
    1. **Confidentiality**: Scrambles the data so it's unreadable.
    2. **Integrity (Authentication)**: Ensures that if an attacker modifies even 1 bit of the encrypted file during transit, the decryption will completely fail (instead of producing a corrupted file).

---

## 🛠️ Installation & Usage

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Start Server**:
   ```bash
   python app.py
   ```
3. **Access**:
   - Open `http://localhost:5000` on your browser.
   - For other devices on the network, use your IP: `http://192.168.x.x:5000`

## 📁 Project Structure

- `app.py`: Flask server + WebSocket logic. Handles peer connections and relays encrypted data.
- `crypto_engine.py`: Handles all the heavy lifting: generating keys, deriving secrets, and AES encryption.
- `static/app.js`: Frontend logic. Manages UI state, WebSocket events, and API calls.
- `templates/index.html`: The user interface.
