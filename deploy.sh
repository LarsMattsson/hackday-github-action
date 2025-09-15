#!/bin/bash

# GitHub Vulnerability Scanner - Cloud Run Deployment Script

set -e

# Configuration
PROJECT_ID=${1:-"your-gcp-project-id"}
REGION=${2:-"us-central1"}
SERVICE_NAME="github-vulnerability-scanner"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "Deploying GitHub Vulnerability Scanner to Cloud Run..."
echo "Project ID: ${PROJECT_ID}"
echo "Region: ${REGION}"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "Error: gcloud CLI is not installed. Please install it first."
    exit 1
fi

# Set the project
gcloud config set project ${PROJECT_ID}

# Enable required APIs
echo "Enabling required Google Cloud APIs..."
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com

# Build and push the container image
echo "Building and pushing container image..."
gcloud builds submit --tag ${IMAGE_NAME}

# Create secrets (if they don't exist)
echo "Creating secrets..."
echo "Note: You'll need to manually set the secret values after creation."

gcloud secrets create github-webhook-secret --replication-policy="automatic" || echo "Secret github-webhook-secret already exists"
gcloud secrets create github-app-id --replication-policy="automatic" || echo "Secret github-app-id already exists"
gcloud secrets create github-private-key --replication-policy="automatic" || echo "Secret github-private-key already exists"

# Update the service YAML with the correct project ID
sed "s/PROJECT_ID/${PROJECT_ID}/g" cloudrun-service.yaml > cloudrun-service-deployed.yaml

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run services replace cloudrun-service-deployed.yaml --region=${REGION}

# Allow unauthenticated invocations (for GitHub webhooks)
echo "Allowing unauthenticated invocations..."
gcloud run services add-iam-policy-binding ${SERVICE_NAME} \
    --member="allUsers" \
    --role="roles/run.invoker" \
    --region=${REGION}

# Get the service URL
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} --region=${REGION} --format="value(status.url)")

echo ""
echo "Deployment completed successfully!"
echo "Service URL: ${SERVICE_URL}"
echo ""
echo "Next steps:"
echo "1. Set your GitHub secrets:"
echo "   gcloud secrets versions add github-webhook-secret --data-file=webhook-secret.txt"
echo "   gcloud secrets versions add github-app-id --data-file=app-id.txt"
echo "   gcloud secrets versions add github-private-key --data-file=private-key.pem"
echo ""
echo "2. Configure your GitHub App webhook URL: ${SERVICE_URL}/webhook"
echo ""
echo "3. Test the deployment: curl ${SERVICE_URL}/health"

# Clean up temporary file
rm -f cloudrun-service-deployed.yaml