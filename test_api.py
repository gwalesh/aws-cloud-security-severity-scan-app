#!/usr/bin/env python3
"""
Simple script to test the API endpoints
"""
import requests
import json
import sys

API_BASE = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get(f"{API_BASE}/health")
        print(f"✅ Health Check: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Health Check Failed: {e}")
        return False

def test_findings():
    """Test findings endpoint"""
    try:
        response = requests.get(f"{API_BASE}/findings")
        print(f"✅ Findings Endpoint: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Total findings: {data.get('total', 0)}")
            print(f"   Findings count: {len(data.get('findings', []))}")
        else:
            print(f"   Error: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Findings Endpoint Failed: {e}")
        return False

def test_scan():
    """Test scan endpoint with sample data"""
    try:
        sample_data = {
            "resources": [
                {
                    "type": "s3",
                    "name": "test-bucket",
                    "account_id": "123456789012",
                    "properties": {"public": True}
                }
            ]
        }
        
        response = requests.post(f"{API_BASE}/scan", json=sample_data)
        print(f"✅ Scan Endpoint: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Scan result: {data}")
        else:
            print(f"   Error: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Scan Endpoint Failed: {e}")
        return False

def main():
    print("🧪 Testing Cloud Security Monitor API")
    print("="*40)
    
    tests = [
        ("Health Check", test_health),
        ("Findings Endpoint", test_findings),
        ("Scan Endpoint", test_scan)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "="*40)
    print("📊 Test Results:")
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    if all_passed:
        print("\n🎉 All tests passed! API is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Check the API server.")
        sys.exit(1)

if __name__ == "__main__":
    main()
