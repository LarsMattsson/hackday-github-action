# GitHub Vulnerability Scanner

A Google Cloud Run application that integrates with GitHub repositories to automatically scan dependencies for known security vulnerabilities.

## Features

- 🔍 **Multi-language support**: Analyzes dependencies for Python, Node.js, Java/Maven, Ruby, Go, and Rust projects
- 🚨 **Real-time scanning**: Automatically scans on push events and pull requests
- 📊 **Vulnerability reporting**: Creates GitHub issues and PR comments for found vulnerabilities
- 🔒 **Secure webhook handling**: Validates GitHub webhook signatures
- ☁️ **Cloud Run ready**: Designed for serverless deployment on Google Cloud

## Supported Dependency Files

| Language | Files |
|----------|-------|
| Python | `requirements.txt` |
| Node.js | `package.json` |
| Java | `pom.xml`, `build.gradle` |
| Ruby | `Gemfile` |
| Go | `go.mod` |
| Rust | `Cargo.toml` |

## Architecture

The application consists of:
- **Flask web server** for handling GitHub webhooks
- **Dependency analyzer** for extracting dependencies from various file formats
- **Vulnerability scanner** using OSV (Open Source Vulnerabilities) API and Safety CLI
- **GitHub integration** for creating issues and PR comments

## Quick Start

### Prerequisites

- Google Cloud Project with billing enabled
- GitHub App created and installed on repositories
- Docker (for local development)

### 1. Create a GitHub App

1. Go to GitHub Settings > Developer settings > GitHub Apps
2. Click "New GitHub App"
3. Configure:
   - **Name**: Your app name
   - **Homepage URL**: Your app URL
   - **Webhook URL**: `https://your-cloudrun-url/webhook`
   - **Webhook secret**: Generate a secure secret
   - **Permissions**:
     - Repository permissions: Contents (read), Issues (write), Pull requests (write)
     - Subscribe to events: Push, Pull request

### 2. Deploy to Cloud Run

```bash
# Clone the repository
git clone <repository-url>
cd hackday-github-action

# Deploy to Cloud Run
./deploy.sh your-gcp-project-id us-central1
```

### 3. Configure Secrets

```bash
# Set GitHub webhook secret
echo "your-webhook-secret" | gcloud secrets versions add github-webhook-secret --data-file=-

# Set GitHub App ID
echo "your-app-id" | gcloud secrets versions add github-app-id --data-file=-

# Set GitHub private key (download from GitHub App settings)
gcloud secrets versions add github-private-key --data-file=path/to/private-key.pem
```

### 4. Test the Deployment

```bash
# Health check
curl https://your-service-url/health

# Test webhook (with proper GitHub signature)
curl -X POST https://your-service-url/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: ping" \
  -H "X-Hub-Signature-256: sha256=..." \
  -d '{"zen": "Design for failure."}'
```

## Local Development

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your GitHub App credentials
```

### Run Locally

```bash
# Start the Flask development server
python app.py

# The server will run on http://localhost:8080
```

### Test Locally with ngrok

```bash
# Install ngrok
npm install -g ngrok

# Expose local server
ngrok http 8080

# Use the ngrok URL as your GitHub webhook URL
```

## API Endpoints

### Health Check
```
GET /health
```
Returns the health status of the application.

### GitHub Webhook
```
POST /webhook
```
Handles GitHub webhook events. Requires proper GitHub signature validation.

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_WEBHOOK_SECRET` | Secret for validating GitHub webhooks | Yes |
| `GITHUB_APP_ID` | GitHub App ID | Yes |
| `GITHUB_PRIVATE_KEY` | GitHub App private key (PEM format) | Yes |
| `PORT` | Port to run the server on | No (default: 8080) |
| `LOG_LEVEL` | Logging level | No (default: INFO) |

### GitHub App Permissions

Required permissions for the GitHub App:
- **Repository permissions**:
  - Contents: Read (to access dependency files)
  - Issues: Write (to create vulnerability issues)
  - Pull requests: Write (to comment on PRs)
- **Subscribe to events**:
  - Push (to scan on code changes)
  - Pull request (to scan PR changes)

## How It Works

1. **Webhook Reception**: GitHub sends webhook events to `/webhook` endpoint
2. **Signature Validation**: Validates webhook signature using the shared secret
3. **Event Processing**: Handles different event types (push, pull_request)
4. **Dependency Extraction**: Analyzes repository files to extract dependencies
5. **Vulnerability Scanning**: Checks dependencies against vulnerability databases
6. **Reporting**: Creates GitHub issues or PR comments for found vulnerabilities

## Vulnerability Sources

- **OSV (Open Source Vulnerabilities)**: Comprehensive vulnerability database
- **Safety CLI**: Python-specific vulnerability database
- **Additional sources**: Can be extended to include more databases

## Security Considerations

- Webhook signature validation prevents unauthorized requests
- Secrets are stored securely in Google Secret Manager
- Application runs with minimal privileges
- No sensitive data is logged

## Monitoring and Logging

The application includes:
- Health check endpoint for monitoring
- Structured logging for debugging
- Cloud Run built-in metrics and logging

## Troubleshooting

### Common Issues

1. **Webhook signature validation fails**
   - Verify the webhook secret matches between GitHub App and Cloud Run
   - Check that the secret is properly stored in Secret Manager

2. **Dependencies not detected**
   - Ensure dependency files are in supported formats
   - Check application logs for parsing errors

3. **Vulnerabilities not found**
   - Verify network connectivity to vulnerability databases
   - Check if the dependency version is correctly parsed

### Debugging

```bash
# View Cloud Run logs
gcloud logs read --service=github-vulnerability-scanner --region=us-central1

# Check service status
gcloud run services describe github-vulnerability-scanner --region=us-central1
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.