/**
 * Secure File Sharing P2P - Frontend Application
 * WebSocket-based peer discovery and file transfer
 */

// Initialize Socket.IO
const socket = io();

// Application state
// Generate simple peer ID (e.g., ABC-123)
function generateSimplePeerId() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';

    let id = '';
    // 3 random letters
    for (let i = 0; i < 3; i++) {
        id += letters.charAt(Math.floor(Math.random() * letters.length));
    }
    id += '-';
    // 3 random numbers
    for (let i = 0; i < 3; i++) {
        id += numbers.charAt(Math.floor(Math.random() * numbers.length));
    }

    return id;
}

// Application state
const state = {
    peerId: generateSimplePeerId(),
    userName: null,
    userRole: null,
    sessionId: null,
    publicKey: null,
    sharedSecret: null,
    connectedPeer: null,
    pendingRequest: null,
    selectedFile: null,
    isConnected: false,
    receivingFile: {
        chunks: [],
        totalChunks: 0,
        filename: null
    }
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

    // Show appropriate UI based on role
    if (state.userRole === 'receiver') {
        document.getElementById('receiver-id-display').style.display = 'block';
        document.getElementById('sender-search-panel').style.display = 'none';
        document.getElementById('peer-id-display').textContent = state.peerId;
        document.getElementById('discovery-title').textContent = 'Your Peer ID';
        document.getElementById('discovery-subtitle').textContent = 'Share this ID with senders';
    } else {
        document.getElementById('receiver-id-display').style.display = 'none';
        document.getElementById('sender-search-panel').style.display = 'block';
        document.getElementById('discovery-title').textContent = 'Find Receiver';
        document.getElementById('discovery-subtitle').textContent = 'Enter receiver\'s Peer ID';
    }
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
    // Disabled auto-discovery - peers are now found manually
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

socket.on('peer_found', (data) => {
    console.log('Peer found:', data);
    displayFoundPeer(data);
});

socket.on('peer_not_found', () => {
    const searchResult = document.getElementById('search-result');
    searchResult.innerHTML = `
        <div class="empty-state">
            <p>Peer not found</p>
            <span>Please check the ID and try again</span>
        </div>
    `;
});

socket.on('receive_file_chunk', (data) => {
    handleFileChunk(data);
});

socket.on('receive_file_complete', (data) => {
    handleFileComplete(data);
});

socket.on('file_preparation_started', (data) => {
    console.log('Sender is preparing file:', data.filename);
    addLog(`Sender is preparing file: ${data.filename}`);
    showProgress('Sender is encrypting file...', 0);
    updateStatusIcon('encryption-icon', 'pending');
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

// Copy Peer ID function
function copyPeerId() {
    const peerId = state.peerId;
    navigator.clipboard.writeText(peerId).then(() => {
        const btn = event.target.closest('button');
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<span class="btn-icon">✓</span> Copied!';
        setTimeout(() => {
            btn.innerHTML = originalHTML;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy ID. Please copy manually.');
    });
}

// Search for peer by ID
function searchPeer() {
    const searchInput = document.getElementById('peer-search-input');
    const targetPeerId = searchInput.value.trim();

    if (!targetPeerId) {
        alert('Please enter a Peer ID');
        return;
    }

    if (targetPeerId === state.peerId) {
        alert('You cannot connect to yourself!');
        return;
    }

    // Clear previous results
    const searchResult = document.getElementById('search-result');
    searchResult.innerHTML = '<div class="empty-state"><p>Searching...</p></div>';

    // Emit search request
    socket.emit('find_peer', { target_peer_id: targetPeerId });
}

// Display found peer
function displayFoundPeer(peer) {
    const searchResult = document.getElementById('search-result');
    searchResult.innerHTML = `
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
    `;
}

// ==================== Connection Management ====================

function sendConnectionRequest(targetPeerId, targetName) {
    socket.emit('send_connection_request', {
        target_peer_id: targetPeerId,
        sender_peer_id: state.peerId,
        sender_name: state.userName
    });

    addLog(`Sent connection request to ${targetName}`);

    // Show alert to user
    alert(`Connection request sent to ${targetName}!\nWaiting for them to accept...`);
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

        // Notify receiver that we're preparing the file
        socket.emit('notify_file_preparation', {
            target_peer_id: state.connectedPeer,
            filename: state.selectedFile.name
        });

        button.innerHTML = '<span class="btn-icon">⏳</span> Encrypting...';

        updateStatusIcon('encryption-icon', 'pending');
        addLog('Encrypting file...');
        showProgress('Encrypting file...', 0);

        // Encrypt file with progress tracking
        const formData = new FormData();
        formData.append('file', state.selectedFile);
        formData.append('shared_secret', state.sharedSecret);

        const result = await uploadWithProgress('/api/files/encrypt', formData, (progress) => {
            updateProgress('Encrypting...', progress);
        });

        updateStatusIcon('encryption-icon', 'success');
        addLog('File encrypted successfully', 'success');

        // Send encrypted file in chunks
        updateStatusIcon('transfer-icon', 'pending');
        addLog('Sending encrypted file to peer...');

        await sendFileInChunks(result.encrypted_data, state.selectedFile.name);

        updateStatusIcon('transfer-icon', 'success');
        addLog('File sent successfully!', 'success');
        hideProgress();

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
        hideProgress();
    }
}

// Upload with progress tracking
function uploadWithProgress(url, formData, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const progress = (e.loaded / e.total) * 100;
                onProgress(progress);
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                resolve(JSON.parse(xhr.responseText));
            } else {
                reject(new Error('Upload failed'));
            }
        });

        xhr.addEventListener('error', () => reject(new Error('Upload failed')));

        xhr.open('POST', url);
        xhr.send(formData);
    });
}

// Send file in chunks
async function sendFileInChunks(encryptedData, filename) {
    const CHUNK_SIZE = 64 * 1024; // 64KB chunks
    const totalSize = encryptedData.length;
    const totalChunks = Math.ceil(totalSize / CHUNK_SIZE);

    for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, totalSize);
        const chunk = encryptedData.substring(start, end);

        socket.emit('send_file_chunk', {
            target_peer_id: state.connectedPeer,
            chunk_data: chunk,
            chunk_index: i,
            total_chunks: totalChunks,
            filename: filename
        });

        const progress = ((i + 1) / totalChunks) * 100;
        updateProgress('Sending file...', progress);

        // Small delay to prevent overwhelming the socket
        await new Promise(resolve => setTimeout(resolve, 10));
    }

    // Notify completion
    socket.emit('send_file_complete', {
        target_peer_id: state.connectedPeer,
        filename: filename
    });
}

// Handle file chunk reception
function handleFileChunk(data) {
    const { chunk_data, chunk_index, total_chunks, filename } = data;

    // Initialize if first chunk
    if (chunk_index === 0) {
        state.receivingFile.chunks = [];
        state.receivingFile.totalChunks = total_chunks;
        state.receivingFile.filename = filename;
        addLog(`Receiving file: ${filename}`);
        updateStatusIcon('transfer-icon', 'pending');
        showProgress('Receiving file...', 0);
    }

    // Store chunk
    state.receivingFile.chunks[chunk_index] = chunk_data;

    // Update progress
    const progress = ((chunk_index + 1) / total_chunks) * 100;
    updateProgress('Receiving file...', progress);
    addLog(`Received chunk ${chunk_index + 1}/${total_chunks}`);
}

// Handle file transfer completion
async function handleFileComplete(data) {
    try {
        const { filename } = data;

        // Combine all chunks
        const encryptedData = state.receivingFile.chunks.join('');

        addLog('File received completely');
        updateStatusIcon('transfer-icon', 'success');
        updateStatusIcon('encryption-icon', 'pending');
        updateProgress('Decrypting file...', 0);
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
        updateProgress('Complete!', 100);

        setTimeout(() => hideProgress(), 2000);

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

        // Reset receiving state
        state.receivingFile = { chunks: [], totalChunks: 0, filename: null };

    } catch (error) {
        console.error('Error decrypting file:', error);
        addLog('Failed to decrypt file', 'error');
        updateStatusIcon('encryption-icon', 'error');
        hideProgress();
    }
}

// Legacy handler for backward compatibility
async function handleReceivedFile(encryptedData, filename) {
    try {
        addLog('Received encrypted file');
        updateStatusIcon('transfer-icon', 'success');
        updateStatusIcon('encryption-icon', 'pending');
        addLog('Decrypting file...');
        showProgress('Decrypting file...', 0);

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
        updateProgress('Complete!', 100);
        setTimeout(() => hideProgress(), 2000);

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
        hideProgress();
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

// Progress bar functions
function showProgress(label, progress) {
    const container = document.getElementById('progress-container');
    const progressLabel = document.getElementById('progress-label');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');

    container.style.display = 'block';
    progressLabel.textContent = label;
    progressBar.style.width = progress + '%';
    progressText.textContent = Math.round(progress) + '%';
}

function updateProgress(label, progress) {
    const progressLabel = document.getElementById('progress-label');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');

    progressLabel.textContent = label;
    progressBar.style.width = progress + '%';
    progressText.textContent = Math.round(progress) + '%';
}

function hideProgress() {
    const container = document.getElementById('progress-container');
    container.style.display = 'none';
}

// Attach send file function to button
document.addEventListener('DOMContentLoaded', () => {
    const sendBtn = document.getElementById('send-file-btn');
    if (sendBtn) {
        sendBtn.addEventListener('click', sendFile);
    }

    // Add Enter key support for peer search
    const searchInput = document.getElementById('peer-search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchPeer();
            }
        });
    }
});

console.log('Secure File Sharing P2P Application Loaded');
console.log('Peer ID:', state.peerId);
