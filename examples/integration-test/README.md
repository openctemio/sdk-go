# SDK Integration Test

This example demonstrates how to use the OpenCTEM SDK to:

1. Send heartbeat to the API
2. Push security findings
3. Push discovered assets
4. Push combined reports (findings + assets)
5. Poll for commands from the server

## Prerequisites

1. **Backend API running** with migration applied:
   ```bash
   cd api
   make docker-migrate-up
   make docker-dev
   ```

2. **Create a source and get API key**:
   ```bash
   # First, get a JWT token (login to get token)
   # Then create a source:
   curl -X POST http://localhost:8080/api/v1/sources \
     -H "Authorization: Bearer <JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "test-scanner",
       "type": "scanner",
       "description": "Test scanner for SDK integration"
     }'
   ```

   Save the `api_key` from the response - it's only shown once!

## Running the Test

### Option 1: Using environment variable

```bash
export API_KEY="your-api-key-here"

cd sdk
go run ./examples/integration-test/
```

### Option 2: Using command line flag

```bash
cd sdk
go run ./examples/integration-test/ -api-key="your-api-key-here"
```

### Full options

```bash
go run ./examples/integration-test/ \
  -url="http://localhost:8080" \
  -api-key="your-api-key-here" \
  -source-id="optional-source-id" \
  -verbose=true
```

## Expected Output

```
=== OpenCTEM SDK Integration Test ===
Base URL: http://localhost:8080

1. Testing connection (heartbeat)...
.openctem] Heartbeat sent: running
   ✓ Heartbeat successful

2. Testing push findings...
.openctem] Pushing 3 findings to http://localhost:8080/api/v1/agent/ingest
.openctem] Push completed: 3 findings created, 0 updated
   Findings created: 3, updated: 0
   ✓ Push findings successful

3. Testing push assets...
.openctem] Pushing 3 assets to http://localhost:8080/api/v1/agent/ingest
   Assets created: 3, updated: 0
   ✓ Push assets successful

4. Testing push combined report...
.openctem] Pushing 2 findings to http://localhost:8080/api/v1/agent/ingest
   Assets created: 1, Findings created: 2
   ✓ Push combined successful

5. Testing poll commands...
.openctem] Polling commands from http://localhost:8080/api/v1/agent/commands?limit=10
.openctem] Received 0 commands
   Pending commands: 0
   ✓ Poll commands successful

=== Integration Test Complete ===
```

## Troubleshooting

### "API key required"
- Make sure you pass the API key via `-api-key` flag or `API_KEY` environment variable

### "Invalid API key" (401)
- The API key might be incorrect or the source was deleted
- Create a new source to get a fresh API key

### "Connection refused"
- Make sure the backend API is running on the specified URL
- Default URL is `http://localhost:8080`

### "no target asset" errors
- This is normal for findings without explicit targets
- The backend creates a default asset for the source
