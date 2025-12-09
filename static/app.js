/**
 * Secure File Sharing P2P - Frontend Application
 * WebRTC DataChannel-based peer-to-peer file transfer with client-side encryption
 */

// Initialize Socket.IO
const socket = io();

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
    cryptoKey: null, // Web Crypto API key
    connectedPeer: null,
    pendingRequest: null,
    selectedFile: null,
    isConnected: false,

    // WebRTC
    peerConnection: null,
    dataChannel: null,

    // File receiving
    receivingFile: {
        chunks: [],
        totalChunks: 0,
        filename: null,
        fileSize: 0
    }
};

// WebRTC Configuration
const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
    ]
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

// ==================== WebRTC Signaling Events ====================

socket.on('offer', async (data) => {
    console.log('Received WebRTC offer from:', data.from_peer_id);
    try {
        await setupWebRTCConnection(false); // Receiver
        await state.peerConnection.setRemoteDescription(new RTCSessionDescription(data.offer));
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);

        socket.emit('answer', {
            target_peer_id: data.from_peer_id,
            answer: answer,
            sender_peer_id: state.peerId
        });

        console.log('Sent WebRTC answer');
    } catch (error) {
        console.error('Error handling offer:', error);
        addLog('Failed to establish WebRTC connection', 'error');
    }
});

socket.on('answer', async (data) => {
    console.log('Received WebRTC answer from:', data.from_peer_id);
    try {
        await state.peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
        console.log('WebRTC answer processed');
    } catch (error) {
        console.error('Error handling answer:', error);
    }
});

socket.on('ice_candidate', async (data) => {
    console.log('Received ICE candidate from:', data.from_peer_id);
    try {
        if (data.candidate && state.peerConnection) {
            await state.peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
        }
    } catch (error) {
        console.error('Error adding ICE candidate:', error);
    }
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

    const searchResult = document.getElementById('search-result');
    searchResult.innerHTML = '<div class="empty-state"><p>Searching...</p></div>';

    socket.emit('find_peer', { target_peer_id: targetPeerId });
}

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

    const peerName = 'Peer';
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
    // Close WebRTC connection
    if (state.dataChannel) {
        state.dataChannel.close();
        state.dataChannel = null;
    }
    if (state.peerConnection) {
        state.peerConnection.close();
        state.peerConnection = null;
    }

    state.connectedPeer = null;
    state.isConnected = false;
    state.sharedSecret = null;
    state.cryptoKey = null;

    // Show peer discovery, hide file transfer
    document.getElementById('peer-discovery-panel').style.display = 'block';
    document.getElementById('file-transfer-panel').style.display = 'none';

    resetStatusIcons();
    addLog('Disconnected from peer');
}

// ==================== WebRTC Setup ====================

async function setupWebRTCConnection(isInitiator) {
    try {
        console.log('Setting up WebRTC connection, isInitiator:', isInitiator);

        state.peerConnection = new RTCPeerConnection(rtcConfig);

        // Handle ICE candidates
        state.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                console.log('Sending ICE candidate');
                socket.emit('ice_candidate', {
                    target_peer_id: state.connectedPeer,
                    candidate: event.candidate,
                    sender_peer_id: state.peerId
                });
            }
        };

        // Monitor connection state
        state.peerConnection.onconnectionstatechange = () => {
            console.log('WebRTC connection state:', state.peerConnection.connectionState);
            if (state.peerConnection.connectionState === 'connected') {
                addLog('WebRTC peer-to-peer connection established!', 'success');
            } else if (state.peerConnection.connectionState === 'failed') {
                addLog('WebRTC connection failed', 'error');
            }
        };

        state.peerConnection.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', state.peerConnection.iceConnectionState);
        };

        if (isInitiator) {
            // Sender creates the data channel
            state.dataChannel = state.peerConnection.createDataChannel('fileTransfer');
            setupDataChannel(state.dataChannel);

            // Create and send offer
            const offer = await state.peerConnection.createOffer();
            await state.peerConnection.setLocalDescription(offer);

            socket.emit('offer', {
                target_peer_id: state.connectedPeer,
                offer: offer,
                sender_peer_id: state.peerId
            });

            console.log('Sent WebRTC offer');
        } else {
            // Receiver waits for data channel
            state.peerConnection.ondatachannel = (event) => {
                console.log('Received data channel');
                state.dataChannel = event.channel;
                setupDataChannel(state.dataChannel);
            };
        }

    } catch (error) {
        console.error('Error setting up WebRTC:', error);
        addLog('Failed to setup WebRTC connection', 'error');
    }
}

function setupDataChannel(channel) {
    channel.binaryType = 'arraybuffer';

    channel.onopen = () => {
        console.log('DataChannel opened');
        addLog('Secure data channel established', 'success');
        updateStatusIcon('transfer-icon', 'success');

        // Enable file sending if sender
        if (state.userRole === 'sender') {
            document.getElementById('send-file-btn').disabled = false;
        }
    };

    channel.onclose = () => {
        console.log('DataChannel closed');
        addLog('Data channel closed');
    };

    channel.onerror = (error) => {
        console.error('DataChannel error:', error);
        addLog('Data channel error', 'error');
    };

    channel.onmessage = async (event) => {
        await handleDataChannelMessage(event.data);
    };
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

        // Import shared secret as CryptoKey for Web Crypto API
        const keyData = base64ToArrayBuffer(state.sharedSecret);
        state.cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        addLog('Shared secret derived successfully', 'success');
        updateStatusIcon('key-exchange-icon', 'success');

        // Setup WebRTC connection after key exchange
        if (state.userRole === 'sender') {
            await setupWebRTCConnection(true); // Sender initiates
        } else {
            // Receiver will setup when offer arrives
        }

    } catch (error) {
        console.error('Error deriving secret:', error);
        addLog('Failed to derive shared secret', 'error');
        updateStatusIcon('key-exchange-icon', 'error');
    }
}

// ==================== Client-Side Encryption ====================

async function encryptChunk(chunk) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for GCM
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        state.cryptoKey,
        chunk
    );

    return { iv, data: new Uint8Array(encrypted) };
}

async function decryptChunk(iv, encryptedData) {
    const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        state.cryptoKey,
        encryptedData
    );

    return new Uint8Array(decrypted);
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
    if (!state.selectedFile || !state.cryptoKey || !state.dataChannel) {
        alert('Please ensure connection is established and file is selected');
        return;
    }

    if (state.dataChannel.readyState !== 'open') {
        alert('Data channel is not ready. Please wait...');
        return;
    }

    try {
        const button = document.getElementById('send-file-btn');
        button.disabled = true;
        button.innerHTML = '<span class="btn-icon">⏳</span> Encrypting & Sending...';

        updateStatusIcon('encryption-icon', 'pending');
        addLog('Starting file transfer...');
        showProgress('Preparing file...', 0);

        const file = state.selectedFile;
        const CHUNK_SIZE = 64 * 1024; // 64KB chunks (increased for better performance)
        const BUFFER_THRESHOLD = 1024 * 1024; // 1MB threshold (balanced for speed and stability)
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

        // Configure bufferedAmountLowThreshold for better backpressure handling
        state.dataChannel.bufferedAmountLowThreshold = BUFFER_THRESHOLD;

        // Send file metadata first
        const metadata = {
            type: 'metadata',
            filename: file.name,
            fileSize: file.size,
            totalChunks: totalChunks
        };
        state.dataChannel.send(JSON.stringify(metadata));
        addLog(`Sending ${file.name} (${totalChunks} chunks)`);

        // Helper function to wait for buffer to drain using event-based approach
        const waitForBufferDrain = () => {
            return new Promise((resolve) => {
                if (state.dataChannel.bufferedAmount <= BUFFER_THRESHOLD) {
                    resolve();
                } else {
                    console.log(`Waiting for buffer to drain... (${state.dataChannel.bufferedAmount} bytes buffered)`);
                    const onBufferedAmountLow = () => {
                        state.dataChannel.removeEventListener('bufferedamountlow', onBufferedAmountLow);
                        resolve();
                    };
                    state.dataChannel.addEventListener('bufferedamountlow', onBufferedAmountLow);

                    // Fallback timeout in case event doesn't fire
                    setTimeout(() => {
                        state.dataChannel.removeEventListener('bufferedamountlow', onBufferedAmountLow);
                        resolve();
                    }, 5000);
                }
            });
        };

        // Helper function to send data with retry logic
        const sendWithRetry = async (data, maxRetries = 3) => {
            for (let attempt = 0; attempt < maxRetries; attempt++) {
                try {
                    // Wait for buffer to drain before sending
                    await waitForBufferDrain();

                    // Attempt to send
                    state.dataChannel.send(data);
                    return; // Success
                } catch (error) {
                    if (error.message && error.message.includes('send queue is full')) {
                        console.warn(`Send queue full, retry ${attempt + 1}/${maxRetries}`);
                        // Wait with exponential backoff
                        await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
                    } else {
                        throw error; // Re-throw non-queue errors
                    }
                }
            }
            throw new Error('Failed to send after maximum retries');
        };

        // Read and send file in chunks
        let offset = 0;
        let chunkIndex = 0;

        while (offset < file.size) {
            const chunk = file.slice(offset, offset + CHUNK_SIZE);
            const arrayBuffer = await chunk.arrayBuffer();

            // Encrypt chunk
            const { iv, data } = await encryptChunk(arrayBuffer);

            // Combine IV + encrypted data
            const combined = new Uint8Array(iv.length + data.length);
            combined.set(iv, 0);
            combined.set(data, iv.length);

            // Send encrypted chunk with retry logic
            await sendWithRetry(combined);

            chunkIndex++;
            offset += CHUNK_SIZE;

            const progress = (chunkIndex / totalChunks) * 100;
            updateProgress(`Sending... (${chunkIndex}/${totalChunks})`, progress);
        }

        // Wait for final buffer drain before sending completion signal
        await waitForBufferDrain();

        // Send completion signal
        state.dataChannel.send(JSON.stringify({ type: 'complete' }));

        updateStatusIcon('encryption-icon', 'success');
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
        addLog('Failed to send file: ' + error.message, 'error');
        updateStatusIcon('encryption-icon', 'error');
        updateStatusIcon('transfer-icon', 'error');
        hideProgress();

        const button = document.getElementById('send-file-btn');
        button.innerHTML = '<span class="btn-icon">🚀</span> Encrypt & Send File';
        button.disabled = false;
    }
}

// ==================== File Receiving ====================

async function handleDataChannelMessage(data) {
    try {
        // Check if it's a JSON message (metadata or control)
        if (typeof data === 'string' || data instanceof String) {
            const message = JSON.parse(data);

            if (message.type === 'metadata') {
                // Initialize file reception
                state.receivingFile = {
                    chunks: [],
                    totalChunks: message.totalChunks,
                    filename: message.filename,
                    fileSize: message.fileSize
                };

                addLog(`Receiving file: ${message.filename}`);
                updateStatusIcon('transfer-icon', 'pending');
                updateStatusIcon('encryption-icon', 'pending');
                showProgress('Receiving file...', 0);

            } else if (message.type === 'complete') {
                // File transfer complete
                await finalizeFileReception();
            }
        } else {
            // Binary data - encrypted chunk
            const combined = new Uint8Array(data);
            const iv = combined.slice(0, 12);
            const encryptedData = combined.slice(12);

            // Decrypt chunk
            const decryptedChunk = await decryptChunk(iv, encryptedData);
            state.receivingFile.chunks.push(decryptedChunk);

            const progress = (state.receivingFile.chunks.length / state.receivingFile.totalChunks) * 100;
            updateProgress(`Receiving... (${state.receivingFile.chunks.length}/${state.receivingFile.totalChunks})`, progress);
        }
    } catch (error) {
        console.error('Error handling data channel message:', error);
        addLog('Error receiving file chunk', 'error');
    }
}

async function finalizeFileReception() {
    try {
        addLog('File received completely');
        updateStatusIcon('transfer-icon', 'success');
        updateProgress('Decrypting...', 100);

        // Combine all decrypted chunks
        const totalSize = state.receivingFile.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const fileData = new Uint8Array(totalSize);
        let offset = 0;

        for (const chunk of state.receivingFile.chunks) {
            fileData.set(chunk, offset);
            offset += chunk.length;
        }

        updateStatusIcon('encryption-icon', 'success');
        addLog('File decrypted successfully!', 'success');
        updateProgress('Complete!', 100);

        setTimeout(() => hideProgress(), 2000);

        // Create download button
        const blob = new Blob([fileData]);
        const url = URL.createObjectURL(blob);

        const receivedFileInfo = document.getElementById('received-file-info');
        receivedFileInfo.innerHTML = `
            <div class="file-info active">
                <strong>Received File:</strong> ${state.receivingFile.filename}<br>
                <strong>Size:</strong> ${(state.receivingFile.fileSize / 1024).toFixed(2)} KB<br>
                <strong>Status:</strong> Decrypted and ready to download
            </div>
            <button class="btn btn-primary btn-block" onclick="downloadFile('${url}', '${state.receivingFile.filename}')">
                <span class="btn-icon">💾</span>
                Download ${state.receivingFile.filename}
            </button>
        `;
        receivedFileInfo.style.display = 'block';

        // Reset receiving state
        state.receivingFile = { chunks: [], totalChunks: 0, filename: null, fileSize: 0 };

    } catch (error) {
        console.error('Error finalizing file reception:', error);
        addLog('Failed to process received file', 'error');
        updateStatusIcon('encryption-icon', 'error');
        hideProgress();
    }
}

function downloadFile(url, filename) {
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

// ==================== Utility Functions ====================

function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// ==================== Event Listeners ====================

document.addEventListener('DOMContentLoaded', () => {
    const sendBtn = document.getElementById('send-file-btn');
    if (sendBtn) {
        sendBtn.addEventListener('click', sendFile);
    }

    const searchInput = document.getElementById('peer-search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                searchPeer();
            }
        });
    }
});

console.log('Secure File Sharing P2P Application Loaded (WebRTC DataChannel)');
console.log('Peer ID:', state.peerId);
