from app import app

if __name__ == '__main__':
    # Check if SocketIO is available for WebSocket support
    if hasattr(app, 'socketio'):
        app.socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)
