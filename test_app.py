import unittest
import json
import os
from unittest.mock import Mock, patch, MagicMock
from app import app, verify_signature, create_vulnerability_comment
from dependency_analyzer import DependencyAnalyzer
from vulnerability_scanner import VulnerabilityScanner

class TestGitHubVulnerabilityScanner(unittest.TestCase):
    """Test cases for the GitHub Vulnerability Scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        
        # Mock environment variables by patching the module globals
        self.webhook_secret_patcher = patch('app.GITHUB_WEBHOOK_SECRET', 'test-secret')
        self.app_id_patcher = patch('app.GITHUB_APP_ID', '12345')
        self.private_key_patcher = patch('app.GITHUB_PRIVATE_KEY', 'test-key')
        
        self.webhook_secret_patcher.start()
        self.app_id_patcher.start()
        self.private_key_patcher.start()
    
    def tearDown(self):
        """Clean up after tests."""
        self.webhook_secret_patcher.stop()
        self.app_id_patcher.stop()
        self.private_key_patcher.stop()
    
    def test_health_check(self):
        """Test the health check endpoint."""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
    
    def test_webhook_signature_validation(self):
        """Test webhook signature validation."""
        payload = b'{"test": "data"}'
        secret = 'test-secret'
        
        import hmac
        import hashlib
        
        # Create valid signature
        hash_object = hmac.new(
            secret.encode('utf-8'),
            msg=payload,
            digestmod=hashlib.sha256
        )
        valid_signature = "sha256=" + hash_object.hexdigest()
        
        # Mock the secret for this test
        with patch('app.GITHUB_WEBHOOK_SECRET', secret):
            # Test valid signature
            self.assertTrue(verify_signature(payload, valid_signature))
            
            # Test invalid signature
            self.assertFalse(verify_signature(payload, "sha256=invalid"))
            
            # Test missing signature
            self.assertFalse(verify_signature(payload, None))
    
    def test_dependency_analyzer_python(self):
        """Test Python dependency parsing."""
        mock_repo = Mock()
        analyzer = DependencyAnalyzer(mock_repo)
        
        requirements_content = """
        flask==2.3.3
        requests>=2.31.0
        # This is a comment
        django==4.2.0
        """
        
        dependencies = analyzer._parse_python_requirements(requirements_content)
        
        self.assertEqual(len(dependencies), 3)
        self.assertEqual(dependencies[0]['name'], 'flask')
        self.assertEqual(dependencies[0]['version'], '2.3.3')
        self.assertEqual(dependencies[0]['ecosystem'], 'pypi')
    
    def test_dependency_analyzer_package_json(self):
        """Test Node.js package.json parsing."""
        mock_repo = Mock()
        analyzer = DependencyAnalyzer(mock_repo)
        
        package_json_content = """
        {
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "^29.0.0"
            }
        }
        """
        
        dependencies = analyzer._parse_package_json(package_json_content)
        
        self.assertEqual(len(dependencies), 3)
        
        # Check express dependency
        express_dep = next(d for d in dependencies if d['name'] == 'express')
        self.assertEqual(express_dep['version'], '4.18.0')
        self.assertEqual(express_dep['ecosystem'], 'npm')
        self.assertFalse(express_dep.get('dev_dependency', False))
        
        # Check jest dev dependency
        jest_dep = next(d for d in dependencies if d['name'] == 'jest')
        self.assertTrue(jest_dep['dev_dependency'])
    
    def test_vulnerability_comment_creation(self):
        """Test vulnerability comment formatting."""
        vulnerabilities = [
            {
                'package': 'flask',
                'version': '1.0.0',
                'severity': 'High',
                'description': 'Test vulnerability',
                'fixed_in': '1.1.0',
                'cve': 'CVE-2023-1234'
            },
            {
                'package': 'requests',
                'version': '2.0.0',
                'severity': 'Medium',
                'description': 'Another test vulnerability',
                'fixed_in': '2.1.0',
                'cve': 'CVE-2023-5678'
            }
        ]
        
        comment = create_vulnerability_comment(vulnerabilities)
        
        self.assertIn('Security Vulnerabilities Found', comment)
        self.assertIn('flask 1.0.0', comment)
        self.assertIn('High', comment)
        self.assertIn('CVE-2023-1234', comment)
        self.assertIn('requests 2.0.0', comment)
        self.assertIn('Medium', comment)
        self.assertIn('CVE-2023-5678', comment)
    
    @patch('app.GITHUB_WEBHOOK_SECRET', 'test-secret')
    @patch('app.GITHUB_PRIVATE_KEY', 'test-key')
    @patch('app.Github')
    def test_webhook_push_event(self, mock_github):
        """Test handling of push webhook events."""
        # Mock GitHub objects
        mock_repo = Mock()
        mock_github.return_value.get_repo.return_value = mock_repo
        
        # Mock payload
        payload = {
            'repository': {
                'full_name': 'test/repo'
            }
        }
        
        # Mock signature
        import hmac
        import hashlib
        payload_data = json.dumps(payload).encode('utf-8')
        hash_object = hmac.new(
            'test-secret'.encode('utf-8'),
            msg=payload_data,
            digestmod=hashlib.sha256
        )
        signature = "sha256=" + hash_object.hexdigest()
        
        with patch('app.DependencyAnalyzer') as mock_analyzer, \
             patch('app.VulnerabilityScanner') as mock_scanner:
            
            # Mock analyzer and scanner
            mock_analyzer.return_value.extract_dependencies.return_value = []
            mock_scanner.return_value.scan_dependencies.return_value = []
            
            response = self.client.post(
                '/webhook',
                data=json.dumps(payload),
                headers={
                    'Content-Type': 'application/json',
                    'X-GitHub-Event': 'push',
                    'X-Hub-Signature-256': signature
                }
            )
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data['message'], 'Dependencies analyzed')
    
    def test_vulnerability_scanner_deduplication(self):
        """Test vulnerability deduplication."""
        scanner = VulnerabilityScanner()
        
        vulnerabilities = [
            {
                'package': 'flask',
                'version': '1.0.0',
                'cve': 'CVE-2023-1234',
                'vulnerability_id': 'VULN-1'
            },
            {
                'package': 'flask',
                'version': '1.0.0',
                'cve': 'CVE-2023-1234',  # Duplicate
                'vulnerability_id': 'VULN-1'
            },
            {
                'package': 'requests',
                'version': '2.0.0',
                'cve': 'CVE-2023-5678',
                'vulnerability_id': 'VULN-2'
            }
        ]
        
        deduplicated = scanner._deduplicate_vulnerabilities(vulnerabilities)
        
        self.assertEqual(len(deduplicated), 2)
        packages = [v['package'] for v in deduplicated]
        self.assertIn('flask', packages)
        self.assertIn('requests', packages)

if __name__ == '__main__':
    unittest.main()