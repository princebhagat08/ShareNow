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


@socketio.on('find_peer')
def handle_find_peer(data):
    """Find a specific peer by ID"""
    target_peer_id = data.get('target_peer_id')
    requester_sid = request.sid
    
    if target_peer_id in active_peers:
        peer_data = active_peers[target_peer_id]
        # Send peer details back to requester
        socketio.emit('peer_found', {
            'peer_id': target_peer_id,
            'name': peer_data['name'],
            'role': peer_data['role'],
            'status': peer_data.get('status', 'available')
        }, room=requester_sid)
        
        print(f"Peer found: {target_peer_id}")
    else:
        socketio.emit('peer_not_found', {}, room=requester_sid)
        print(f"Peer not found: {target_peer_id}")


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


# ==================== WebRTC Signaling ====================

@socketio.on('offer')
def handle_webrtc_offer(data):
    """Forward WebRTC offer to target peer"""
    target_peer_id = data.get('target_peer_id')
    offer = data.get('offer')
    sender_peer_id = data.get('sender_peer_id')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        socketio.emit('offer', {
            'offer': offer,
            'from_peer_id': sender_peer_id
        }, room=target_sid)
        
        print(f"WebRTC offer forwarded from {sender_peer_id} to {target_peer_id}")


@socketio.on('answer')
def handle_webrtc_answer(data):
    """Forward WebRTC answer to target peer"""
    target_peer_id = data.get('target_peer_id')
    answer = data.get('answer')
    sender_peer_id = data.get('sender_peer_id')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        socketio.emit('answer', {
            'answer': answer,
            'from_peer_id': sender_peer_id
        }, room=target_sid)
        
        print(f"WebRTC answer forwarded from {sender_peer_id} to {target_peer_id}")


@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    """Forward ICE candidate to target peer"""
    target_peer_id = data.get('target_peer_id')
    candidate = data.get('candidate')
    sender_peer_id = data.get('sender_peer_id')
    
    if target_peer_id in active_peers:
        target_sid = active_peers[target_peer_id]['sid']
        
        socketio.emit('ice_candidate', {
            'candidate': candidate,
            'from_peer_id': sender_peer_id
        }, room=target_sid)
        
        print(f"ICE candidate forwarded from {sender_peer_id} to {target_peer_id}")



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



@app.route('/api/peers', methods=['GET'])
def get_peers():
    """Get list of active peers"""
    return jsonify({'peers': get_peers_list()})


if __name__ == '__main__':
    print("=" * 60)
    print("Secure File Sharing Application with WebRTC P2P")
    print("=" * 60)
    print("Server starting on http://localhost:5000")
    print("Encryption: AES-256-GCM (Client-Side)")
    print("Key Exchange: Diffie-Hellman (2048-bit)")
    print("Peer Discovery: WebSocket (SocketIO)")
    print("File Transfer: WebRTC DataChannel (P2P)")
    print("=" * 60)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
