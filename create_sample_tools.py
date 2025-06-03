#!/usr/bin/env python3
"""
Script to create sample MCP tools in the database
"""
import json
from app import create_app, db
from models import Tool

def create_sample_tools():
    """Create sample tools for demonstration"""
    app = create_app()
    
    with app.app_context():
        # Check if tools already exist
        if Tool.query.count() > 0:
            print("Tools already exist in database")
            return
        
        print("Creating sample tools...")
        
        # Echo tool
        echo_tool = Tool()
        echo_tool.name = 'echo'
        echo_tool.description = 'Echo back the input message'
        echo_tool.schema = json.dumps({
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Message to echo back"
                }
            },
            "required": ["message"]
        })
        echo_tool.endpoint = None
        echo_tool.method = 'POST'
        echo_tool.is_active = True
        
        # System info tool
        system_tool = Tool()
        system_tool.name = 'system_info'
        system_tool.description = 'Get system information'
        system_tool.schema = json.dumps({
            "type": "object",
            "properties": {},
            "required": []
        })
        system_tool.endpoint = None
        system_tool.method = 'POST'
        system_tool.is_active = True
        
        # Calculator tool
        calc_tool = Tool()
        calc_tool.name = 'calculator'
        calc_tool.description = 'Perform basic mathematical calculations'
        calc_tool.schema = json.dumps({
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "Mathematical expression to evaluate (e.g., '2 + 3 * 4')"
                }
            },
            "required": ["expression"]
        })
        calc_tool.endpoint = None
        calc_tool.method = 'POST'
        calc_tool.is_active = True
        
        # Add all tools
        db.session.add(echo_tool)
        db.session.add(system_tool)
        db.session.add(calc_tool)
        db.session.commit()
        
        print(f"Created {Tool.query.count()} sample tools")

if __name__ == '__main__':
    create_sample_tools()