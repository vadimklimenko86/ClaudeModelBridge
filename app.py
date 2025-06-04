import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


def create_app():
    # Create the app
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET",
                                    "dev-secret-key-change-in-production")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Configure CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Configure the database
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///mcp_server.db")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Initialize extensions
    db.init_app(app)
    # Disable WebSocket temporarily to avoid resource issues
    # socketio.init_app(app, cors_allowed_origins="*",
    #                  async_mode='threading',
    #                  logger=False,
    #                  engineio_logger=False)

    # Register routes
    from routes import main_bp, api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/mcp')

    with app.app_context():
        # Import models to ensure tables are created
        import models
        db.create_all()

        # Initialize MCP server
        from mcp_server import mcp_manager
        mcp_manager.initialize()

    return app


app = create_app()
