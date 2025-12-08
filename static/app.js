/**
 * Secure File Sharing P2P - Frontend Application
 * WebSocket-based peer discovery and file transfer
 */

// Initialize Socket.IO
const socket = io();

// Application state
const state = {
    peerId: 'peer-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    userName: null,
    userRole: null,
    sessionId: null,
    publicKey: null,
    sharedSecret: null,
    connectedPeer: null,
    pendingRequest: null,
    selectedFile: null,
    isConnected: false
};

// ==================== Screen Navigation ====================

function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

function selectRole(role) {
    state.userRole = role;
    showScreen('name-input-screen');
}

function submitName() {
    const nameInput = document.getElementById('user-name-input');
    const name = nameInput.value.trim();

    if (!name) {
        alert('Please enter your name');
        return;
    }

    state.userName = name;
    state.sessionId = state.peerId;

    // Show main app
    showScreen('main-app-screen');

    // Update UI
    document.getElementById('user-name-display').textContent = name;
    document.getElementById('user-role-display').textContent = state.userRole + ' Mode';
    document.getElementById('user-avatar').textContent = name.charAt(0).toUpperCase();

    // Register with server
    registerPeer();

    // Generate keys automatically
    generateKeys();
}

// ==================== WebSocket Events ====================

socket.on('connect', () => {
    console.log('Connected to server');
    updateConnectionStatus('connected');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateConnectionStatus('disconnected');
});

socket.on('peers_updated', (data) => {
    console.log('Peers updated:', data.peers);
    updatePeersList(data.peers);
});

socket.on('connection_request', (data) => {
    console.log('Connection request from:', data.from_name);
    showConnectionRequest(data.from_peer_id, data.from_name);
});

socket.on('connection_accepted', (data) => {
    console.log('Connection accepted by:', data.peer_name);
    establishConnection(data.peer_id, data.peer_name);
});

socket.on('connection_rejected', () => {
    alert('Connection request was rejected');
});

socket.on('receive_public_key', (data) => {
    console.log('Received public key from peer');
    handleReceivedPublicKey(data.public_key);
});

socket.on('receive_encrypted_file', (data) => {
    console.log('Received encrypted file');
    handleReceivedFile(data.encrypted_data, data.filename);
});

// ==================== Peer Management ====================

function registerPeer() {
    socket.emit('register_peer', {
        peer_id: state.peerId,
        name: state.userName,
        role: state.userRole
    });
}

function updateConnectionStatus(status) {
    const indicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');

    indicator.className = 'status-indicator ' + status;

    if (status === 'connected') {
        statusText.textContent = 'Connected';
    } else if (status === 'disconnected') {
        statusText.textContent = 'Disconnected';
    } else {
        statusText.textContent = 'Connecting...';
    }
}

function updatePeersList(peers) {
    const peersList = document.getElementById('peers-list');

    // Filter out self and peers with opposite role
    const availablePeers = peers.filter(peer =>
        peer.peer_id !== state.peerId &&
        peer.role !== state.userRole
    );

    if (availablePeers.length === 0) {
        peersList.innerHTML = `
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                    <circle cx="9" cy="7" r="4"/>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
                <p>No peers found</p>
                <span>Waiting for ${state.userRole === 'sender' ? 'receivers' : 'senders'} to join...</span>
            </div>
        `;
        return;
    }

    peersList.innerHTML = availablePeers.map(peer => `
        <div class="peer-item">
            <div class="peer-info">
                <div class="peer-avatar">${peer.name.charAt(0).toUpperCase()}</div>
                <div class="peer-details">
                    <h4>${peer.name}</h4>
                    <p>${peer.role}</p>
                </div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="sendConnectionRequest('${peer.peer_id}', '${peer.name}')">
                <span class="btn-icon">🔗</span>
                Connect
            </button>
        </div>
    `).join('');
}

// ==================== Connection Management ====================

function sendConnectionRequest(targetPeerId, targetName) {
    socket.emit('send_connection_request', {
        target_peer_id: targetPeerId,
        sender_peer_id: state.peerId,
        sender_name: state.userName
    });

    addLog(`Sent connection request to ${targetName}`);
}

function showConnectionRequest(fromPeerId, fromName) {
    state.pendingRequest = fromPeerId;

    const modal = document.getElementById('connection-modal');
    document.getElementById('modal-message').textContent =
        `${fromName} wants to ${state.userRole === 'receiver' ? 'send you a file' : 'receive a file from you'}`;

    modal.classList.add('active');
}

function acceptConnection() {
    const modal = document.getElementById('connection-modal');
    modal.classList.remove('active');

    socket.emit('accept_connection', {
        requester_peer_id: state.pendingRequest,
        accepter_peer_id: state.peerId
    });

    // Get peer name from peers list
    const peerName = 'Peer'; // We'll get this from the request
    establishConnection(state.pendingRequest, peerName);
}

function rejectConnection() {
    const modal = document.getElementById('connection-modal');
    modal.classList.remove('active');

    socket.emit('reject_connection', {
        requester_peer_id: state.pendingRequest
    });

    state.pendingRequest = null;
}

function establishConnection(peerId, peerName) {
    state.connectedPeer = peerId;
    state.isConnected = true;

    // Hide peer discovery, show file transfer
    document.getElementById('peer-discovery-panel').style.display = 'none';
    document.getElementById('file-transfer-panel').style.display = 'block';
    document.getElementById('connected-peer-name').textContent = `Connected to ${peerName}`;

    // Show appropriate interface
    if (state.userRole === 'sender') {
        document.getElementById('sender-interface').style.display = 'block';
        document.getElementById('receiver-interface').style.display = 'none';
    } else {
        document.getElementById('sender-interface').style.display = 'none';
        document.getElementById('receiver-interface').style.display = 'block';
    }

    addLog(`Connected to ${peerName}`, 'success');

    // Exchange public keys automatically
    exchangePublicKeys();
}

function disconnectPeer() {
    state.connectedPeer = null;
    state.isConnected = false;
    state.sharedSecret = null;

    // Show peer discovery, hide file transfer
    document.getElementById('peer-discovery-panel').style.display = 'block';
    document.getElementById('file-transfer-panel').style.display = 'none';

    // Reset status icons
    resetStatusIcons();

    addLog('Disconnected from peer');
}

// ==================== Cryptography ====================

async function generateKeys() {
    try {
        const response = await fetch('/api/keys/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: state.sessionId })
        });

        const result = await response.json();
        state.publicKey = result.public_key;

        console.log('Keys generated successfully');
    } catch (error) {
        console.error('Error generating keys:', error);
        alert('Failed to generate encryption keys');
    }
}

function exchangePublicKeys() {
    if (!state.publicKey || !state.connectedPeer) {
        return;
    }

    // Send our public key to peer
    socket.emit('send_public_key', {
        target_peer_id: state.connectedPeer,
        public_key: state.publicKey,
        sender_peer_id: state.peerId
    });

    addLog('Sent public key to peer');
    updateStatusIcon('key-exchange-icon', 'pending');
}

async function handleReceivedPublicKey(peerPublicKey) {
    try {
        addLog('Received public key from peer');

        // Derive shared secret
        const response = await fetch('/api/keys/derive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: state.sessionId,
                peer_public_key: peerPublicKey
            })
        });

        const result = await response.json();
        state.sharedSecret = result.shared_secret;

        addLog('Shared secret derived successfully', 'success');
        updateStatusIcon('key-exchange-icon', 'success');

        // Enable file sending if sender
        if (state.userRole === 'sender') {
            document.getElementById('send-file-btn').disabled = false;
        }
    } catch (error) {
        console.error('Error deriving secret:', error);
        addLog('Failed to derive shared secret', 'error');
        updateStatusIcon('key-exchange-icon', 'error');
    }
}

// ==================== File Handling ====================

// File upload setup
const fileUploadArea = document.getElementById('file-upload-area');
const fileInput = document.getElementById('file-input');

if (fileUploadArea) {
    fileUploadArea.addEventListener('click', () => fileInput.click());

    fileUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileUploadArea.style.borderColor = '#667eea';
    });

    fileUploadArea.addEventListener('dragleave', () => {
        fileUploadArea.style.borderColor = '';
    });

    fileUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        fileUploadArea.style.borderColor = '';
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
}

function handleFileSelect(file) {
    state.selectedFile = file;

    const fileInfo = document.getElementById('file-info');
    fileInfo.innerHTML = `
        <strong>Selected File:</strong> ${file.name}<br>
        <strong>Size:</strong> ${(file.size / 1024).toFixed(2)} KB<br>
        <strong>Type:</strong> ${file.type || 'Unknown'}
    `;
    fileInfo.classList.add('active');

    addLog(`File selected: ${file.name}`);
}

async function sendFile() {
    if (!state.selectedFile || !state.sharedSecret || !state.connectedPeer) {
        alert('Please select a file and ensure connection is established');
        return;
    }

    try {
        const button = document.getElementById('send-file-btn');
        button.disabled = true;
        button.innerHTML = '<span class="btn-icon">⏳</span> Encrypting...';

        updateStatusIcon('encryption-icon', 'pending');
        addLog('Encrypting file...');

        // Encrypt file
        const formData = new FormData();
        formData.append('file', state.selectedFile);
        formData.append('shared_secret', state.sharedSecret);

        const response = await fetch('/api/files/encrypt', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        updateStatusIcon('encryption-icon', 'success');
        addLog('File encrypted successfully', 'success');

        // Send encrypted file to peer
        updateStatusIcon('transfer-icon', 'pending');
        addLog('Sending encrypted file to peer...');

        socket.emit('send_encrypted_file', {
            target_peer_id: state.connectedPeer,
            encrypted_data: result.encrypted_data,
            filename: state.selectedFile.name
        });

        updateStatusIcon('transfer-icon', 'success');
        addLog('File sent successfully!', 'success');

        button.innerHTML = '<span class="btn-icon">✓</span> File Sent!';
        setTimeout(() => {
            button.innerHTML = '<span class="btn-icon">🚀</span> Encrypt & Send File';
            button.disabled = false;
        }, 3000);

    } catch (error) {
        console.error('Error sending file:', error);
        addLog('Failed to send file', 'error');
        updateStatusIcon('encryption-icon', 'error');
        updateStatusIcon('transfer-icon', 'error');
    }
}

async function handleReceivedFile(encryptedData, filename) {
    try {
        addLog('Received encrypted file');
        updateStatusIcon('transfer-icon', 'success');
        updateStatusIcon('encryption-icon', 'pending');
        addLog('Decrypting file...');

        // Decrypt file
        const response = await fetch('/api/files/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encrypted_data: encryptedData,
                shared_secret: state.sharedSecret
            })
        });

        const result = await response.json();

        updateStatusIcon('encryption-icon', 'success');
        addLog('File decrypted successfully!', 'success');

        // Show download button
        const receivedFileInfo = document.getElementById('received-file-info');
        receivedFileInfo.innerHTML = `
            <div class="file-info active">
                <strong>Received File:</strong> ${filename}<br>
                <strong>Status:</strong> Decrypted and ready to download
            </div>
            <button class="btn btn-primary btn-block" onclick="downloadDecryptedFile('${result.decrypted_data}', '${filename}')">
                <span class="btn-icon">💾</span>
                Download ${filename}
            </button>
        `;
        receivedFileInfo.style.display = 'block';

    } catch (error) {
        console.error('Error decrypting file:', error);
        addLog('Failed to decrypt file', 'error');
        updateStatusIcon('encryption-icon', 'error');
    }
}

function downloadDecryptedFile(decryptedDataB64, filename) {
    // Convert base64 to binary
    const binaryString = atob(decryptedDataB64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    addLog(`Downloaded: ${filename}`, 'success');
}

// ==================== UI Helpers ====================

function updateStatusIcon(iconId, status) {
    const icon = document.getElementById(iconId);
    if (!icon) return;

    if (status === 'success') {
        icon.textContent = '✓';
        icon.style.color = '#10b981';
    } else if (status === 'error') {
        icon.textContent = '✕';
        icon.style.color = '#ef4444';
    } else if (status === 'pending') {
        icon.textContent = '⏳';
        icon.style.color = '#fbbf24';
    }
}

function resetStatusIcons() {
    updateStatusIcon('key-exchange-icon', 'pending');
    updateStatusIcon('encryption-icon', 'pending');
    updateStatusIcon('transfer-icon', 'pending');
}

function addLog(message, type = 'info') {
    const logElement = document.getElementById('transfer-log');
    if (!logElement) return;

    logElement.classList.add('active');

    const timestamp = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${timestamp}] ${message}`;

    logElement.appendChild(entry);
    logElement.scrollTop = logElement.scrollHeight;
}

// Attach send file function to button
document.addEventListener('DOMContentLoaded', () => {
    const sendBtn = document.getElementById('send-file-btn');
    if (sendBtn) {
        sendBtn.addEventListener('click', sendFile);
    }
});

console.log('Secure File Sharing P2P Application Loaded');
console.log('Peer ID:', state.peerId);
