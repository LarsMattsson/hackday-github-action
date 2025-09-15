import os
import json
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify
from github import Github
from dependency_analyzer import DependencyAnalyzer
from vulnerability_scanner import VulnerabilityScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
GITHUB_WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')
GITHUB_APP_ID = os.environ.get('GITHUB_APP_ID')
GITHUB_PRIVATE_KEY = os.environ.get('GITHUB_PRIVATE_KEY')

def verify_signature(payload_body, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256."""
    if not signature_header or not GITHUB_WEBHOOK_SECRET:
        return False
    
    hash_object = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    if not hmac.compare_digest(expected_signature, signature_header):
        return False
    return True

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Cloud Run."""
    return jsonify({'status': 'healthy'}), 200

@app.route('/webhook', methods=['POST'])
def github_webhook():
    """Handle GitHub webhook events."""
    try:
        # Verify the webhook signature
        signature_header = request.headers.get('X-Hub-Signature-256')
        if not verify_signature(request.data, signature_header):
            logger.warning('Invalid webhook signature')
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse the webhook payload
        payload = request.get_json()
        event_type = request.headers.get('X-GitHub-Event')
        
        logger.info(f'Received {event_type} event')
        
        # Process different event types
        if event_type == 'push':
            return handle_push_event(payload)
        elif event_type == 'pull_request':
            return handle_pull_request_event(payload)
        elif event_type == 'installation':
            return handle_installation_event(payload)
        else:
            logger.info(f'Unhandled event type: {event_type}')
            return jsonify({'message': 'Event received'}), 200
            
    except Exception as e:
        logger.error(f'Error processing webhook: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

def handle_push_event(payload):
    """Handle push events to analyze dependencies."""
    try:
        repository = payload['repository']
        repo_name = repository['full_name']
        
        logger.info(f'Analyzing dependencies for {repo_name}')
        
        # Initialize GitHub client
        g = Github(GITHUB_PRIVATE_KEY)
        repo = g.get_repo(repo_name)
        
        # Analyze dependencies
        analyzer = DependencyAnalyzer(repo)
        dependencies = analyzer.extract_dependencies()
        
        # Scan for vulnerabilities
        scanner = VulnerabilityScanner()
        vulnerabilities = scanner.scan_dependencies(dependencies)
        
        # Create or update issue if vulnerabilities found
        if vulnerabilities:
            create_vulnerability_issue(repo, vulnerabilities)
        
        return jsonify({
            'message': 'Dependencies analyzed',
            'vulnerabilities_found': len(vulnerabilities)
        }), 200
        
    except Exception as e:
        logger.error(f'Error handling push event: {str(e)}')
        return jsonify({'error': 'Failed to analyze dependencies'}), 500

def handle_pull_request_event(payload):
    """Handle pull request events."""
    try:
        if payload['action'] not in ['opened', 'synchronize']:
            return jsonify({'message': 'PR event ignored'}), 200
        
        repository = payload['repository']
        pull_request = payload['pull_request']
        repo_name = repository['full_name']
        pr_number = pull_request['number']
        
        logger.info(f'Analyzing PR #{pr_number} for {repo_name}')
        
        # Initialize GitHub client
        g = Github(GITHUB_PRIVATE_KEY)
        repo = g.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        # Analyze changed dependencies
        analyzer = DependencyAnalyzer(repo)
        changed_deps = analyzer.analyze_pr_changes(pr)
        
        if changed_deps:
            scanner = VulnerabilityScanner()
            vulnerabilities = scanner.scan_dependencies(changed_deps)
            
            # Add comment to PR if vulnerabilities found
            if vulnerabilities:
                comment_body = create_vulnerability_comment(vulnerabilities)
                pr.create_issue_comment(comment_body)
        
        return jsonify({
            'message': 'PR analyzed',
            'changed_dependencies': len(changed_deps)
        }), 200
        
    except Exception as e:
        logger.error(f'Error handling PR event: {str(e)}')
        return jsonify({'error': 'Failed to analyze PR'}), 500

def handle_installation_event(payload):
    """Handle GitHub App installation events."""
    action = payload['action']
    installation = payload['installation']
    
    logger.info(f'GitHub App {action} for installation {installation["id"]}')
    
    return jsonify({'message': f'Installation {action}'}), 200

def create_vulnerability_issue(repo, vulnerabilities):
    """Create a GitHub issue for found vulnerabilities."""
    title = "🚨 Security Vulnerabilities Detected"
    body = create_vulnerability_comment(vulnerabilities)
    
    # Check if issue already exists
    issues = repo.get_issues(state='open', labels=['security', 'vulnerability'])
    for issue in issues:
        if title in issue.title:
            # Update existing issue
            issue.create_comment(f"Updated vulnerability scan results:\n\n{body}")
            return
    
    # Create new issue
    repo.create_issue(
        title=title,
        body=body,
        labels=['security', 'vulnerability']
    )

def create_vulnerability_comment(vulnerabilities):
    """Create formatted comment for vulnerabilities."""
    comment = "## Security Vulnerabilities Found\n\n"
    comment += "The following vulnerabilities were detected in your dependencies:\n\n"
    
    for vuln in vulnerabilities:
        comment += f"### {vuln['package']} {vuln['version']}\n"
        comment += f"**Severity:** {vuln['severity']}\n"
        comment += f"**Description:** {vuln['description']}\n"
        if vuln.get('fixed_in'):
            comment += f"**Fixed in:** {vuln['fixed_in']}\n"
        comment += f"**CVE:** {vuln.get('cve', 'N/A')}\n\n"
    
    comment += "\n💡 **Recommendation:** Update the affected packages to their latest secure versions."
    return comment

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)