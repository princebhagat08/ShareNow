# Secure File Sharing - WebRTC P2P

A peer-to-peer encrypted file sharing application using **WebRTC DataChannel** for direct file transfer with **AES-256-GCM** encryption and **Diffie-Hellman** key exchange.

## 🚀 Features

- ✅ **True Peer-to-Peer**: Files transfer directly between browsers via WebRTC DataChannel
- ✅ **End-to-End Encryption**: AES-256-GCM encryption performed client-side
- ✅ **Secure Key Exchange**: Diffie-Hellman 2048-bit key agreement
- ✅ **No Backend File Storage**: Backend only handles signaling and peer discovery
- ✅ **LAN Support**: Automatic peer discovery on local networks
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
git clone <repository-url>
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

## 🌐 Network Configuration

### LAN (Local Network)
Works automatically! Peers on the same WiFi/hotspot can connect directly.

### Internet (Different Networks)
Requires STUN/TURN servers. Current configuration uses Google's public STUN:
- `stun:stun.l.google.com:19302`
- `stun:stun1.l.google.com:19302`

For better reliability across restrictive networks, add TURN servers in `app.js`:
```javascript
const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { 
            urls: 'turn:your-turn-server.com:3478',
            username: 'user',
            credential: 'pass'
        }
    ]
};
```

## 📊 Technical Details

### File Transfer Specifications
- **Chunk Size**: 16KB (configurable)
- **Backpressure Threshold**: 16MB buffered data
- **Encryption**: AES-256-GCM with 12-byte IV
- **DataChannel**: Binary mode (`arraybuffer`)

### Message Format
**Metadata Message** (JSON):
```json
{
    "type": "metadata",
    "filename": "example.pdf",
    "fileSize": 1048576,
    "totalChunks": 64
}
```

**Chunk Format** (Binary):
```
[12 bytes IV][N bytes encrypted data]
```

**Completion Message** (JSON):
```json
{
    "type": "complete"
}
```

## 🐛 Troubleshooting

### Connection Issues
- **Firewall**: Ensure UDP ports are open for WebRTC
- **Browser**: Use latest Chrome/Firefox/Edge
- **Network**: Check if both peers can reach STUN servers

### Transfer Failures
- **Large Files**: Browser memory limits may affect very large files (>1GB)
- **Slow Networks**: Increase backpressure threshold if needed
- **Disconnections**: WebRTC will fail if network changes mid-transfer

### Debugging
Open browser console (F12) to see:
- WebRTC connection state
- ICE candidate gathering
- DataChannel status
- Transfer progress logs

## 📝 API Reference

### Socket.IO Events

#### Client → Server
- `register_peer`: Register on network
- `find_peer`: Search for peer by ID
- `send_connection_request`: Request connection
- `accept_connection`: Accept connection request
- `send_public_key`: Send DH public key
- `offer`: Send WebRTC SDP offer
- `answer`: Send WebRTC SDP answer
- `ice_candidate`: Send ICE candidate

#### Server → Client
- `peers_updated`: Peer list changed
- `peer_found`: Peer search result
- `connection_request`: Incoming connection request
- `connection_accepted`: Connection accepted
- `receive_public_key`: Received DH public key
- `offer`: Received WebRTC offer
- `answer`: Received WebRTC answer
- `ice_candidate`: Received ICE candidate

### REST API

#### `POST /api/keys/generate`
Generate Diffie-Hellman key pair
```json
Request: { "session_id": "ABC-123" }
Response: { "success": true, "public_key": "-----BEGIN PUBLIC KEY-----..." }
```

#### `POST /api/keys/derive`
Derive shared secret from peer's public key
```json
Request: { "session_id": "ABC-123", "peer_public_key": "-----BEGIN PUBLIC KEY-----..." }
Response: { "success": true, "shared_secret": "base64_encoded_secret" }
```

## 🔄 Migration from Backend Streaming

This version migrates from backend file streaming to WebRTC P2P:

### What Changed
- ❌ Removed: `/api/files/encrypt` and `/api/files/decrypt` endpoints
- ❌ Removed: Backend file chunk forwarding via Socket.IO
- ✅ Added: WebRTC signaling (offer/answer/ICE)
- ✅ Added: Client-side encryption using Web Crypto API
- ✅ Added: DataChannel binary streaming

### What Stayed
- ✅ Peer discovery and registration
- ✅ Diffie-Hellman key exchange
- ✅ Connection request/accept flow
- ✅ UI/UX and progress tracking

## 📄 License

MIT License - Feel free to use and modify!

## 🤝 Contributing

Contributions welcome! Please test thoroughly before submitting PRs.

---

**Built with ❤️ using Flask, Socket.IO, WebRTC, and Web Crypto API**
