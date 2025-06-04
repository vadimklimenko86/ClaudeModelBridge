#!/usr/bin/env python3
"""
Direct MCP Server using official Python SDK v1.9.2
Pure implementation without Flask/FastAPI wrappers
"""

import asyncio
import logging
from mcp_direct_server import main as mcp_main

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting Direct MCP Server with official Python SDK v1.9.2")
    logger.info("Protocol Version: 2024-11-05")
    logger.info("Transport: stdio (official)")
    
    try:
        asyncio.run(mcp_main())
    except KeyboardInterrupt:
        logger.info("MCP Server stopped")
    except Exception as e:
        logger.error(f"MCP Server error: {e}")
        raise