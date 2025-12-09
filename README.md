# Secure File Sharing - WebRTC P2P

A peer-to-peer encrypted file sharing application using **WebRTC DataChannel** for direct file transfer with **AES-256-GCM** encryption and **Diffie-Hellman** key exchange.

## 🚀 Features

- ✅ **True Peer-to-Peer**: Files transfer directly between browsers via WebRTC DataChannel
- ✅ **End-to-End Encryption**: AES-256-GCM encryption performed client-side
- ✅ **Secure Key Exchange**: Diffie-Hellman 2048-bit key agreement
- ✅ **No Backend File Storage**: Backend only handles signaling and peer discovery
- ✅ **Progress Tracking**: Real-time upload/download progress
- ✅ **Chunked Transfer**: Efficient streaming with backpressure handling
- ✅ **Any File Type**: Support for text, images, videos, documents, etc.

## 🏗️ Architecture

### Backend (Flask + Socket.IO)
**Purpose**: Signaling server only - NO file data passes through backend

- **Peer Discovery**: Register and find peers by ID
- **Connection Management**: Handle connection requests/acceptance
- **Diffie-Hellman**: Generate DH keys and derive shared secret
- **WebRTC Signaling**: Exchange SDP offers/answers and ICE candidates

### Frontend (WebRTC + Web Crypto API)
**Purpose**: All file handling and encryption happens client-side

- **WebRTC DataChannel**: Direct peer-to-peer binary transfer
- **AES-256-GCM Encryption**: Client-side encryption using `window.crypto.subtle`
- **Chunked Streaming**: 16KB chunks with backpressure control
- **File Assembly**: Decrypt and reconstruct file in browser

## 📋 Requirements

- Python 3.7+
- Modern browser with WebRTC support (Chrome, Firefox, Edge, Safari)
- Local network or internet connection

## 🔧 Installation

1. **Clone the repository**
```bash
git clone [<repository-url>](https://github.com/princebhagat08/ShareNow)
cd file-sharing
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the server**
```bash
python app.py
```

4. **Open in browser**
```
http://localhost:5000
```

## 📖 Usage

### Receiver Setup
1. Select **"Receiver"** role
2. Enter your name
3. Copy your **Peer ID** (e.g., `ABC-123`)
4. Share this ID with the sender

### Sender Setup
1. Select **"Sender"** role
2. Enter your name
3. Enter the receiver's **Peer ID**
4. Click **"Search"** and **"Connect"**
5. Wait for receiver to accept
6. Select a file and click **"Encrypt & Send File"**

### Transfer Process
1. **Key Exchange**: Diffie-Hellman keys exchanged via backend
2. **WebRTC Setup**: Peer connection established with ICE/STUN
3. **DataChannel Open**: Secure P2P channel created
4. **File Transfer**: 
   - Sender: Read → Encrypt (AES-GCM) → Send chunks via DataChannel
   - Receiver: Receive chunks → Decrypt → Assemble → Download

## 🔒 Security

### Encryption Flow
```
Sender Side:
File → Read in chunks (16KB) → AES-256-GCM encrypt → WebRTC DataChannel

Receiver Side:
WebRTC DataChannel → AES-256-GCM decrypt → Assemble chunks → Download
```

### Key Exchange
1. Both peers generate DH private/public key pairs (backend)
2. Public keys exchanged via Socket.IO
3. Shared secret derived using DH (backend)
4. Shared secret sent to client and imported as `CryptoKey`
5. AES-256-GCM encryption/decryption uses this key (client-side)

### Security Features
- **No Backend File Access**: Files never touch the server
- **Client-Side Encryption**: Encryption happens in the browser
- **Perfect Forward Secrecy**: New DH keys per session
- **Authenticated Encryption**: GCM mode provides authentication
- **Random IVs**: Each chunk uses a unique 12-byte IV


## 🤝 Contributing

Contributions welcome! Please test thoroughly before submitting PRs.

---

**Built with ❤️ using Flask, Socket.IO, WebRTC, and Web Crypto API**
