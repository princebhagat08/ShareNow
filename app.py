"""
Secure File Sharing Application with Peer Discovery
Flask backend with WebSocket support for real-time peer discovery
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from crypto_engine import DiffieHellmanManager, AESCipher, SessionManager
import base64
import os
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Session manager
session_manager = SessionManager()

# Active peers storage
active_peers = {}  # {session_id: {name, role, sid, timestamp}}


@app.route('/')
def index():
    """Serve the main application page"""
    return render_template('index.html')


# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('connected', {'sid': request.sid})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")
    # Remove from active peers
    to_remove = None
    for peer_id, peer_data in active_peers.items():
        if peer_data['sid'] == request.sid:
            to_remove = peer_id
            break
    
    if to_remove:
        del active_peers[to_remove]
        # Notify all clients about peer list update
        socketio.emit('peers_updated', {'peers': get_peers_list()})


@socketio.on('register_peer')
def handle_register_peer(data):
    """Register a new peer on the network"""
    peer_id = data.get('peer_id')
    name = data.get('name', 'Anonymous')
    role = data.get('role', 'sender')
    
    active_peers[peer_id] = {
        'name': name,
        'role': role,
        'sid': request.sid,
        'timestamp': time.time(),
        'status': 'available'
    }
    
    print(f"Peer registered: {name} ({role}) - {peer_id}")
    
    # Broadcast updated peer list to all clients
    socketio.emit('peers_updated', {'peers': get_peers_list()})
    
    emit('registration_success', {'peer_id': peer_id})


@socketio.on('send_connection_request')
def handle_connection_request(data):
    """Forward connection request to target peer"""
    target_peer_id = data.get('target_peer_id')
    sender_peer_id = data.get('sender_peer_id')
    sender_name = data.get('sender_name')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        # Send request to target peer
        socketio.emit('connection_request', {
            'from_peer_id': sender_peer_id,
            'from_name': sender_name
        }, room=target_sid)
        
        print(f"Connection request: {sender_name} -> {active_peers[target_peer_id]['name']}")


@socketio.on('accept_connection')
def handle_accept_connection(data):
    """Handle connection acceptance"""
    requester_peer_id = data.get('requester_peer_id')
    accepter_peer_id = data.get('accepter_peer_id')
    
    if requester_peer_id in active_peers:
        requester_sid = active_peers[requester_peer_id]['sid']
        
        # Notify requester that connection was accepted
        socketio.emit('connection_accepted', {
            'peer_id': accepter_peer_id,
            'peer_name': active_peers[accepter_peer_id]['name']
        }, room=requester_sid)
        
        print(f"Connection accepted: {active_peers[accepter_peer_id]['name']} accepted {active_peers[requester_peer_id]['name']}")


@socketio.on('reject_connection')
def handle_reject_connection(data):
    """Handle connection rejection"""
    requester_peer_id = data.get('requester_peer_id')
    
    if requester_peer_id in active_peers:
        requester_sid = active_peers[requester_peer_id]['sid']
        
        # Notify requester that connection was rejected
        socketio.emit('connection_rejected', {}, room=requester_sid)
        
        print(f"Connection rejected")


@socketio.on('send_public_key')
def handle_send_public_key(data):
    """Forward public key to connected peer"""
    target_peer_id = data.get('target_peer_id')
    public_key = data.get('public_key')
    sender_peer_id = data.get('sender_peer_id')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        socketio.emit('receive_public_key', {
            'public_key': public_key,
            'from_peer_id': sender_peer_id
        }, room=target_sid)
        
        print(f"Public key forwarded to {active_peers[target_peer_id]['name']}")


@socketio.on('send_encrypted_file')
def handle_send_encrypted_file(data):
    """Forward encrypted file to receiver"""
    target_peer_id = data.get('target_peer_id')
    encrypted_data = data.get('encrypted_data')
    filename = data.get('filename')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        socketio.emit('receive_encrypted_file', {
            'encrypted_data': encrypted_data,
            'filename': filename
        }, room=target_sid)
        
        print(f"Encrypted file forwarded to {active_peers[target_peer_id]['name']}")


def get_peers_list():
    """Get list of active peers"""
    peers_list = []
    for peer_id, peer_data in active_peers.items():
        peers_list.append({
            'peer_id': peer_id,
            'name': peer_data['name'],
            'role': peer_data['role'],
            'status': peer_data.get('status', 'available')
        })
    return peers_list


# ==================== REST API Endpoints ====================

@app.route('/api/keys/generate', methods=['POST'])
def generate_keys():
    """Generate DH key pair for a session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Create or get session
        dh_manager = session_manager.create_session(session_id)
        
        # Generate keys
        public_key_pem = dh_manager.generate_keys()
        
        return jsonify({
            'success': True,
            'public_key': public_key_pem,
            'session_id': session_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/keys/derive', methods=['POST'])
def derive_secret():
    """Derive shared secret from peer's public key"""
    try:
        data = request.json
        session_id = data.get('session_id')
        peer_public_key = data.get('peer_public_key')
        
        if not session_id or not peer_public_key:
            return jsonify({'error': 'Session ID and peer public key required'}), 400
        
        # Get session
        dh_manager = session_manager.get_session(session_id)
        if not dh_manager:
            return jsonify({'error': 'Session not found'}), 404
        
        # Derive shared secret
        shared_secret_b64 = dh_manager.derive_shared_secret(peer_public_key)
        
        return jsonify({
            'success': True,
            'shared_secret': shared_secret_b64
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/encrypt', methods=['POST'])
def encrypt_file():
    """Encrypt uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        shared_secret = request.form.get('shared_secret')
        
        if not shared_secret:
            return jsonify({'error': 'Shared secret required'}), 400
        
        # Read file data
        file_data = file.read()
        original_filename = file.filename
        
        # Encrypt
        encrypted_data_b64 = AESCipher.encrypt(file_data, shared_secret)
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_data_b64,
            'original_filename': original_filename
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt uploaded file"""
    try:
        data = request.json
        encrypted_data_b64 = data.get('encrypted_data')
        shared_secret = data.get('shared_secret')
        
        if not encrypted_data_b64 or not shared_secret:
            return jsonify({'error': 'Encrypted data and shared secret required'}), 400
        
        # Decrypt
        decrypted_data = AESCipher.decrypt(encrypted_data_b64, shared_secret)
        
        # Convert to base64 for JSON response
        decrypted_b64 = base64.b64encode(decrypted_data).decode('utf-8')
        
        return jsonify({
            'success': True,
            'decrypted_data': decrypted_b64
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/peers', methods=['GET'])
def get_peers():
    """Get list of active peers"""
    return jsonify({'peers': get_peers_list()})


if __name__ == '__main__':
    print("=" * 60)
    print("Secure File Sharing Application with Peer Discovery")
    print("=" * 60)
    print("Server starting on http://localhost:5000")
    print("Encryption: AES-256-GCM")
    print("Key Exchange: Diffie-Hellman (2048-bit)")
    print("Peer Discovery: WebSocket (SocketIO)")
    print("=" * 60)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
