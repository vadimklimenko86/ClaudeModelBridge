from app import db
from datetime import datetime
from sqlalchemy import Text, JSON
import json

class Tool(db.Model):
    """Model for registered MCP tools"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(Text)
    schema = db.Column(Text)  # JSON schema as text
    endpoint = db.Column(db.String(255))
    method = db.Column(db.String(10), default='POST')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'schema': json.loads(self.schema) if self.schema else None,
            'endpoint': self.endpoint,
            'method': self.method,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Resource(db.Model):
    """Model for MCP resources"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(Text)
    uri = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'uri': self.uri,
            'mime_type': self.mime_type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }

class MCPLog(db.Model):
    """Model for MCP communication logs"""
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(100))
    method = db.Column(db.String(50), nullable=False)
    request_data = db.Column(Text)  # JSON as text
    response_data = db.Column(Text)  # JSON as text
    status_code = db.Column(db.Integer)
    duration_ms = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'request_id': self.request_id,
            'method': self.method,
            'request_data': json.loads(self.request_data) if self.request_data else None,
            'response_data': json.loads(self.response_data) if self.response_data else None,
            'status_code': self.status_code,
            'duration_ms': self.duration_ms,
            'timestamp': self.timestamp.isoformat()
        }
