# Troubleshooting Guide

## Common Issues and Solutions

### 1. 422 Error when loading findings

**Error**: `Failed to load resource: the server responded with a status of 422 (Unprocessable Content)`

**Causes & Solutions**:

1. **API Server Not Running**
   ```bash
   # Start the API server
   cd api
   python -m app.main
   # OR use the startup script
   python start_api.py
   ```

2. **Database Not Initialized**
   ```bash
   # The database is created automatically when the API starts
   # If you see database errors, delete the existing database file
   rm api/app/security_findings.db
   # Then restart the API
   ```

3. **Port Already in Use**
   ```bash
   # Check if port 8000 is in use
   lsof -i :8000
   # Kill the process if needed
   kill -9 <PID>
   ```

### 2. Frontend Not Loading Data

**Check**:
1. Open browser developer tools (F12)
2. Check the Console tab for errors
3. Check the Network tab to see if API calls are failing

**Solutions**:
1. Make sure the API server is running on `http://localhost:8000`
2. Check for CORS errors - the API should handle this automatically
3. Try refreshing the page

### 3. No Findings Displayed

**Steps to test**:
1. First, run a scan with sample data:
   ```bash
   python test_api.py
   ```
2. Check if the scan creates findings
3. If no findings, check the sample data format

### 4. Database Issues

**Reset Database**:
```bash
# Stop the API server
# Delete the database file
rm api/app/security_findings.db
# Restart the API server
cd api && python -m app.main
```

### 5. Testing the API

**Manual Testing**:
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test findings endpoint
curl http://localhost:8000/findings

# Test scan endpoint
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"resources": [{"type": "s3", "name": "test", "account_id": "123", "properties": {"public": true}}]}'
```

**Automated Testing**:
```bash
python test_api.py
```

### 6. Frontend Issues

**Clear Browser Cache**:
- Hard refresh: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac)
- Clear browser cache and cookies

**Check Console Errors**:
- Open Developer Tools (F12)
- Look for JavaScript errors in the Console tab
- Check Network tab for failed requests

### 7. Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Connection refused` | API not running | Start the API server |
| `422 Unprocessable Content` | Invalid request data | Check API logs, verify data format |
| `CORS error` | Cross-origin request blocked | API should handle CORS automatically |
| `Database locked` | Multiple API instances | Kill all API processes and restart |

### 8. Getting Help

If you're still having issues:

1. **Check the logs**: Look at the terminal where the API is running
2. **Run the test script**: `python test_api.py`
3. **Check browser console**: Look for JavaScript errors
4. **Verify file paths**: Make sure you're in the correct directory

### 9. Quick Start Checklist

- [ ] API server is running (`python start_api.py`)
- [ ] Database file exists (`api/app/security_findings.db`)
- [ ] Frontend opens without errors
- [ ] Can upload and scan sample data
- [ ] Findings appear in the table
- [ ] Details panel opens when clicking "View"
