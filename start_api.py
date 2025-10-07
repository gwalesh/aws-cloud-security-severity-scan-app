#!/usr/bin/env python3
"""
Simple script to start the API server with proper error handling
"""
import sys
import os

# Add the api directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

try:
    import uvicorn
    from app.main import app
    
    print("🚀 Starting Cloud Security Monitor API...")
    print("📍 API will be available at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 Health Check: http://localhost:8000/health")
    print("\n" + "="*50)
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level="info",
        reload=True
    )
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Please make sure you're in the correct directory and have installed the requirements:")
    print("cd api && pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting server: {e}")
    sys.exit(1)
