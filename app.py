from app import socketio, app


if __name__ == "__main__":
    socketio.run(app, allow_unsafe_werkzeug=True )
