import os
import json
import re
import logging
from typing import List, Dict, Any
from github import Repository
from packaging import version

logger = logging.getLogger(__name__)

class DependencyAnalyzer:
    """Analyzes repository dependencies across different languages."""
    
    def __init__(self, repo: Repository):
        self.repo = repo
        self.supported_files = {
            'requirements.txt': self._parse_python_requirements,
            'package.json': self._parse_package_json,
            'Gemfile': self._parse_gemfile,
            'pom.xml': self._parse_maven_pom,
            'build.gradle': self._parse_gradle_build,
            'go.mod': self._parse_go_mod,
            'Cargo.toml': self._parse_cargo_toml
        }
    
    def extract_dependencies(self) -> List[Dict[str, Any]]:
        """Extract all dependencies from the repository."""
        dependencies = []
        
        try:
            # Get repository contents
            contents = self.repo.get_contents("")
            
            for content in contents:
                if content.name in self.supported_files:
                    logger.info(f'Found dependency file: {content.name}')
                    parser = self.supported_files[content.name]
                    file_deps = parser(content.decoded_content.decode('utf-8'))
                    dependencies.extend(file_deps)
            
            # Also check subdirectories for package files
            dependencies.extend(self._scan_subdirectories())
            
        except Exception as e:
            logger.error(f'Error extracting dependencies: {str(e)}')
        
        return dependencies
    
    def analyze_pr_changes(self, pr) -> List[Dict[str, Any]]:
        """Analyze dependency changes in a pull request."""
        changed_deps = []
        
        try:
            files = pr.get_files()
            
            for file in files:
                if file.filename in self.supported_files:
                    logger.info(f'Analyzing changes in {file.filename}')
                    
                    if file.patch:
                        # Parse added lines for new dependencies
                        added_lines = [line[1:] for line in file.patch.split('\n') 
                                     if line.startswith('+') and not line.startswith('+++')]
                        
                        parser = self.supported_files[file.filename]
                        for line in added_lines:
                            if line.strip():
                                deps = parser(line)
                                changed_deps.extend(deps)
        
        except Exception as e:
            logger.error(f'Error analyzing PR changes: {str(e)}')
        
        return changed_deps
    
    def _scan_subdirectories(self) -> List[Dict[str, Any]]:
        """Scan subdirectories for dependency files."""
        dependencies = []
        
        try:
            def scan_directory(path=""):
                contents = self.repo.get_contents(path)
                
                for content in contents:
                    if content.type == "dir":
                        # Recursively scan subdirectories
                        dependencies.extend(scan_directory(content.path))
                    elif content.name in self.supported_files:
                        parser = self.supported_files[content.name]
                        file_deps = parser(content.decoded_content.decode('utf-8'))
                        dependencies.extend(file_deps)
            
            scan_directory()
            
        except Exception as e:
            logger.error(f'Error scanning subdirectories: {str(e)}')
        
        return dependencies
    
    def _parse_python_requirements(self, content: str) -> List[Dict[str, Any]]:
        """Parse Python requirements.txt file."""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                # Parse package name and version
                match = re.match(r'^([a-zA-Z0-9_-]+)([>=<~!]+)([0-9.]+)', line)
                if match:
                    name, operator, ver = match.groups()
                    dependencies.append({
                        'name': name,
                        'version': ver,
                        'operator': operator,
                        'ecosystem': 'pypi',
                        'file': 'requirements.txt'
                    })
                else:
                    # Simple package name without version
                    name_match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                    if name_match:
                        dependencies.append({
                            'name': name_match.group(1),
                            'version': 'latest',
                            'operator': '',
                            'ecosystem': 'pypi',
                            'file': 'requirements.txt'
                        })
        
        return dependencies
    
    def _parse_package_json(self, content: str) -> List[Dict[str, Any]]:
        """Parse Node.js package.json file."""
        dependencies = []
        
        try:
            data = json.loads(content)
            
            # Parse dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, version_spec in data[dep_type].items():
                        # Clean version specification
                        clean_version = re.sub(r'[^0-9.]', '', version_spec)
                        dependencies.append({
                            'name': name,
                            'version': clean_version or version_spec,
                            'operator': '>=',
                            'ecosystem': 'npm',
                            'file': 'package.json',
                            'dev_dependency': dep_type == 'devDependencies'
                        })
        
        except json.JSONDecodeError as e:
            logger.error(f'Error parsing package.json: {str(e)}')
        
        return dependencies
    
    def _parse_gemfile(self, content: str) -> List[Dict[str, Any]]:
        """Parse Ruby Gemfile."""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('gem '):
                # Parse gem line: gem 'name', 'version'
                match = re.match(r"gem ['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
                if match:
                    name = match.group(1)
                    version = match.group(2) or 'latest'
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'operator': '>=',
                        'ecosystem': 'rubygems',
                        'file': 'Gemfile'
                    })
        
        return dependencies
    
    def _parse_maven_pom(self, content: str) -> List[Dict[str, Any]]:
        """Parse Maven pom.xml file."""
        dependencies = []
        
        # Simple regex parsing for Maven dependencies
        dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
        matches = re.findall(dep_pattern, content, re.DOTALL)
        
        for group_id, artifact_id, version in matches:
            dependencies.append({
                'name': f'{group_id}:{artifact_id}',
                'version': version.strip(),
                'operator': '=',
                'ecosystem': 'maven',
                'file': 'pom.xml'
            })
        
        return dependencies
    
    def _parse_gradle_build(self, content: str) -> List[Dict[str, Any]]:
        """Parse Gradle build.gradle file."""
        dependencies = []
        
        # Parse Gradle dependency declarations
        dep_patterns = [
            r"implementation ['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]",
            r"compile ['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]",
            r"api ['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]"
        ]
        
        for pattern in dep_patterns:
            matches = re.findall(pattern, content)
            for group, artifact, version in matches:
                dependencies.append({
                    'name': f'{group}:{artifact}',
                    'version': version,
                    'operator': '=',
                    'ecosystem': 'maven',
                    'file': 'build.gradle'
                })
        
        return dependencies
    
    def _parse_go_mod(self, content: str) -> List[Dict[str, Any]]:
        """Parse Go go.mod file."""
        dependencies = []
        
        in_require_block = False
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('require ('):
                in_require_block = True
                continue
            elif line == ')' and in_require_block:
                in_require_block = False
                continue
            elif in_require_block or line.startswith('require '):
                # Parse require line
                if line.startswith('require '):
                    line = line[8:]  # Remove 'require '
                
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'operator': '=',
                        'ecosystem': 'go',
                        'file': 'go.mod'
                    })
        
        return dependencies
    
    def _parse_cargo_toml(self, content: str) -> List[Dict[str, Any]]:
        """Parse Rust Cargo.toml file."""
        dependencies = []
        
        try:
            import toml
            data = toml.loads(content)
            
            # Parse dependencies section
            if 'dependencies' in data:
                for name, version_spec in data['dependencies'].items():
                    if isinstance(version_spec, str):
                        version = version_spec
                    elif isinstance(version_spec, dict) and 'version' in version_spec:
                        version = version_spec['version']
                    else:
                        version = 'latest'
                    
                    dependencies.append({
                        'name': name,
                        'version': version,
                        'operator': '>=',
                        'ecosystem': 'crates.io',
                        'file': 'Cargo.toml'
                    })
        
        except ImportError:
            logger.warning('toml library not available for Cargo.toml parsing')
        except Exception as e:
            logger.error(f'Error parsing Cargo.toml: {str(e)}')
        
        return dependencies