#!/usr/bin/env python3
"""
OpenGrep Rules Manager
Easy management and customization of detection rules for both ecosystems
"""

import os
import sys
import json
import yaml
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class RulesManager:
    """Manager for OpenGrep/Semgrep rules across ecosystems."""
    
    def __init__(self, rules_dir: str = "opengrep-rules", config_file: str = "utils/rules_config.yaml"):
        self.rules_dir = Path(rules_dir)
        self.config_file = Path(config_file)
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load rules configuration from YAML file."""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        else:
            return self.get_default_config()
    
    def save_config(self):
        """Save current configuration to YAML file."""
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if no config file exists."""
        return {
            'rule_configuration': {
                'global': {
                    'confidence_threshold': 0.6,
                    'enable_experimental_rules': False,
                    'timeout_seconds': 30
                },
                'ecosystems': {
                    'npm': {'enabled': True, 'rules': {}},
                    'pypi': {'enabled': True, 'rules': {}}
                }
            }
        }
    
    def list_rules(self, ecosystem: Optional[str] = None) -> Dict[str, List[str]]:
        """List all available rules, optionally filtered by ecosystem."""
        rules = {}
        
        ecosystems = [ecosystem] if ecosystem else ['npm', 'pypi']
        
        for eco in ecosystems:
            eco_dir = self.rules_dir / eco
            if eco_dir.exists():
                rules[eco] = []
                for rule_file in eco_dir.glob('*.yaml'):
                    rules[eco].append(rule_file.stem)
        
        return rules
    
    def get_rule_info(self, ecosystem: str, rule_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific rule."""
        rule_path = self.rules_dir / ecosystem / f"{rule_name}.yaml"
        
        if not rule_path.exists():
            return None
        
        try:
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            if 'rules' in rule_data and rule_data['rules']:
                rule = rule_data['rules'][0]  # Get first rule
                return {
                    'id': rule.get('id', rule_name),
                    'message': rule.get('message', 'No message'),
                    'severity': rule.get('severity', 'INFO'),
                    'languages': rule.get('languages', []),
                    'patterns': rule.get('patterns', rule.get('pattern', [])),
                    'metadata': rule.get('metadata', {}),
                    'file_path': str(rule_path)
                }
        except Exception as e:
            logger.error(f"Error reading rule {rule_name}: {e}")
        
        return None
    
    def create_rule(self, ecosystem: str, rule_name: str, rule_template: str = 'basic') -> bool:
        """Create a new rule from a template."""
        rule_path = self.rules_dir / ecosystem / f"{rule_name}.yaml"
        
        if rule_path.exists():
            print(f"Rule {rule_name} already exists in {ecosystem}")
            return False
        
        # Ensure directory exists
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get template
        template = self.get_rule_template(rule_template, ecosystem)
        
        # Customize template
        template['rules'][0]['id'] = f"{ecosystem}-{rule_name}"
        template['rules'][0]['message'] = f"Custom rule: {rule_name}"
        
        # Write rule file
        with open(rule_path, 'w') as f:
            yaml.dump(template, f, default_flow_style=False, indent=2)
        
        print(f"Created rule: {rule_path}")
        return True
    
    def get_rule_template(self, template_name: str, ecosystem: str) -> Dict[str, Any]:
        """Get a rule template for the specified ecosystem."""
        if ecosystem == 'npm':
            languages = ['javascript', 'typescript']
        else:  # pypi
            languages = ['python']
        
        templates = {
            'basic': {
                'rules': [{
                    'id': f'{ecosystem}-template-rule',
                    'patterns': [
                        {'pattern': '$FUNCTION(...)'}
                    ],
                    'message': 'Template rule - customize this message',
                    'languages': languages,
                    'severity': 'INFO',
                    'metadata': {
                        'version': 'latest',
                        'endor-category': 'malware-detection',
                        'endor-targets': ['ENDOR_TARGET_PACKAGE'],
                        'confidence': 'LOW'
                    }
                }]
            },
            'string_analysis': {
                'rules': [{
                    'id': f'{ecosystem}-string-analysis',
                    'patterns': [
                        {'pattern-either': [
                            {'pattern': '$VAR = $STR'},
                            {'pattern': '$FUNC(..., $STR, ...)'}
                        ]},
                        {'metavariable-analysis': {
                            'analyzer': 'entropy',
                            'metavariable': '$STR'
                        }},
                        {'metavariable-regex': {
                            'regex': r'(?ms)^[\"\'].{50,}[\"\']$',
                            'metavariable': '$STR'
                        }}
                    ],
                    'message': 'High-entropy string detected',
                    'languages': languages,
                    'severity': 'WARNING',
                    'metadata': {
                        'version': 'latest',
                        'endor-category': 'malware-detection',
                        'confidence': 'MEDIUM'
                    }
                }]
            },
            'api_call': {
                'rules': [{
                    'id': f'{ecosystem}-api-call',
                    'patterns': [
                        {'pattern-either': [
                            {'pattern': '$API($ARGS)'},
                            {'pattern': '$OBJ.$API($ARGS)'}
                        ]},
                        {'metavariable-regex': {
                            'regex': r'(eval|exec|system|spawn)',
                            'metavariable': '$API'
                        }}
                    ],
                    'message': 'Suspicious API call detected',
                    'languages': languages,
                    'severity': 'ERROR',
                    'metadata': {
                        'version': 'latest',
                        'endor-category': 'malware-detection',
                        'confidence': 'HIGH'
                    }
                }]
            }
        }
        
        return templates.get(template_name, templates['basic'])
    
    def edit_rule(self, ecosystem: str, rule_name: str, editor: str = None) -> bool:
        """Open a rule file in an editor for manual editing."""
        rule_path = self.rules_dir / ecosystem / f"{rule_name}.yaml"
        
        if not rule_path.exists():
            print(f"Rule {rule_name} not found in {ecosystem}")
            return False
        
        # Determine editor
        if not editor:
            editor = os.environ.get('EDITOR', 'nano')  # Default to nano
        
        # Open in editor
        try:
            subprocess.run([editor, str(rule_path)])
            print(f"Rule {rule_name} edited")
            return True
        except Exception as e:
            print(f"Error opening editor: {e}")
            return False
    
    def test_rule(self, ecosystem: str, rule_name: str, test_path: str = None) -> Dict[str, Any]:
        """Test a rule against sample code."""
        rule_path = self.rules_dir / ecosystem / f"{rule_name}.yaml"
        
        if not rule_path.exists():
            return {'error': f'Rule {rule_name} not found'}
        
        # Default test path
        if not test_path:
            test_path = f"malware_samples/{ecosystem}"
        
        if not os.path.exists(test_path):
            return {'error': f'Test path {test_path} not found'}
        
        # Run semgrep
        try:
            cmd = [
                'semgrep',
                '--config', str(rule_path),
                '--json',
                test_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = json.loads(result.stdout)
                return {
                    'success': True,
                    'findings': len(output.get('results', [])),
                    'results': output.get('results', [])
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {'error': 'Test timed out'}
        except Exception as e:
            return {'error': f'Test failed: {e}'}
    
    def validate_rule(self, ecosystem: str, rule_name: str) -> Dict[str, Any]:
        """Validate rule syntax."""
        rule_path = self.rules_dir / ecosystem / f"{rule_name}.yaml"
        
        if not rule_path.exists():
            return {'valid': False, 'error': 'Rule file not found'}
        
        try:
            # Check YAML syntax
            with open(rule_path, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            # Check semgrep rule format
            if 'rules' not in rule_data:
                return {'valid': False, 'error': 'Missing "rules" key'}
            
            for rule in rule_data['rules']:
                required_fields = ['id', 'message', 'languages']
                for field in required_fields:
                    if field not in rule:
                        return {'valid': False, 'error': f'Missing required field: {field}'}
                
                # Check if patterns or pattern exists
                if 'patterns' not in rule and 'pattern' not in rule and 'pattern-either' not in rule:
                    return {'valid': False, 'error': 'Missing pattern specification'}
            
            # Try to validate with semgrep
            cmd = ['semgrep', '--validate', '--config', str(rule_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'valid': True, 'message': 'Rule is valid'}
            else:
                return {'valid': False, 'error': result.stderr}
                
        except yaml.YAMLError as e:
            return {'valid': False, 'error': f'YAML syntax error: {e}'}
        except Exception as e:
            return {'valid': False, 'error': f'Validation error: {e}'}
    
    def enable_rule(self, ecosystem: str, rule_category: str, enabled: bool = True):
        """Enable or disable a rule category in configuration."""
        if ecosystem not in self.config['rule_configuration']['ecosystems']:
            self.config['rule_configuration']['ecosystems'][ecosystem] = {'rules': {}}
        
        if 'rules' not in self.config['rule_configuration']['ecosystems'][ecosystem]:
            self.config['rule_configuration']['ecosystems'][ecosystem]['rules'] = {}
        
        if rule_category not in self.config['rule_configuration']['ecosystems'][ecosystem]['rules']:
            self.config['rule_configuration']['ecosystems'][ecosystem]['rules'][rule_category] = {}
        
        self.config['rule_configuration']['ecosystems'][ecosystem]['rules'][rule_category]['enabled'] = enabled
        self.save_config()
        
        status = 'enabled' if enabled else 'disabled'
        print(f"{rule_category} rules {status} for {ecosystem}")
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about available rules."""
        stats = {
            'total_rules': 0,
            'by_ecosystem': {},
            'by_severity': {'INFO': 0, 'WARNING': 0, 'ERROR': 0, 'CRITICAL': 0}
        }
        
        for ecosystem in ['npm', 'pypi']:
            eco_dir = self.rules_dir / ecosystem
            if eco_dir.exists():
                rule_files = list(eco_dir.glob('*.yaml'))
                stats['by_ecosystem'][ecosystem] = len(rule_files)
                stats['total_rules'] += len(rule_files)
                
                # Analyze severity distribution
                for rule_file in rule_files:
                    try:
                        with open(rule_file, 'r') as f:
                            rule_data = yaml.safe_load(f)
                        
                        for rule in rule_data.get('rules', []):
                            severity = rule.get('severity', 'INFO').upper()
                            if severity in stats['by_severity']:
                                stats['by_severity'][severity] += 1
                    except:
                        pass  # Skip invalid files
        
        return stats

def main():
    """Command-line interface for rules management."""
    parser = argparse.ArgumentParser(description="OpenGrep Rules Manager")
    parser.add_argument('--rules-dir', default='opengrep-rules', help='Rules directory')
    parser.add_argument('--config', default='utils/rules_config.yaml', help='Configuration file')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available rules')
    list_parser.add_argument('--ecosystem', choices=['npm', 'pypi'], help='Filter by ecosystem')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Get rule information')
    info_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    info_parser.add_argument('rule_name', help='Rule name')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create new rule')
    create_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    create_parser.add_argument('rule_name', help='Rule name')
    create_parser.add_argument('--template', choices=['basic', 'string_analysis', 'api_call'], 
                              default='basic', help='Rule template')
    
    # Edit command
    edit_parser = subparsers.add_parser('edit', help='Edit rule')
    edit_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    edit_parser.add_argument('rule_name', help='Rule name')
    edit_parser.add_argument('--editor', help='Editor to use')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test rule')
    test_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    test_parser.add_argument('rule_name', help='Rule name')
    test_parser.add_argument('--test-path', help='Path to test files')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate rule')
    validate_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    validate_parser.add_argument('rule_name', help='Rule name')
    
    # Enable/disable commands
    enable_parser = subparsers.add_parser('enable', help='Enable rule category')
    enable_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    enable_parser.add_argument('category', help='Rule category')
    
    disable_parser = subparsers.add_parser('disable', help='Disable rule category')
    disable_parser.add_argument('ecosystem', choices=['npm', 'pypi'], help='Ecosystem')
    disable_parser.add_argument('category', help='Rule category')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show rule statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize manager
    manager = RulesManager(args.rules_dir, args.config)
    
    # Execute command
    if args.command == 'list':
        rules = manager.list_rules(args.ecosystem)
        for ecosystem, rule_list in rules.items():
            print(f"\n{ecosystem.upper()} Rules ({len(rule_list)}):")
            for rule in sorted(rule_list):
                print(f"  - {rule}")
    
    elif args.command == 'info':
        info = manager.get_rule_info(args.ecosystem, args.rule_name)
        if info:
            print(f"\nRule: {info['id']}")
            print(f"Message: {info['message']}")
            print(f"Severity: {info['severity']}")
            print(f"Languages: {', '.join(info['languages'])}")
            print(f"File: {info['file_path']}")
            if info['metadata']:
                print(f"Metadata: {json.dumps(info['metadata'], indent=2)}")
        else:
            print(f"Rule {args.rule_name} not found in {args.ecosystem}")
    
    elif args.command == 'create':
        success = manager.create_rule(args.ecosystem, args.rule_name, args.template)
        if success:
            print(f"Rule {args.rule_name} created successfully")
            print("Use 'rules_manager.py edit' to customize the rule")
    
    elif args.command == 'edit':
        manager.edit_rule(args.ecosystem, args.rule_name, args.editor)
    
    elif args.command == 'test':
        result = manager.test_rule(args.ecosystem, args.rule_name, args.test_path)
        if result.get('success'):
            print(f"Test completed: {result['findings']} findings")
            if result['findings'] > 0:
                print("\nFindings:")
                for finding in result['results'][:5]:  # Show first 5
                    print(f"  - {finding.get('check_id', 'Unknown')}: {finding.get('message', 'No message')}")
        else:
            print(f"Test failed: {result.get('error', 'Unknown error')}")
    
    elif args.command == 'validate':
        result = manager.validate_rule(args.ecosystem, args.rule_name)
        if result['valid']:
            print(f"✓ Rule {args.rule_name} is valid")
        else:
            print(f"✗ Rule {args.rule_name} is invalid: {result['error']}")
    
    elif args.command == 'enable':
        manager.enable_rule(args.ecosystem, args.category, True)
    
    elif args.command == 'disable':
        manager.enable_rule(args.ecosystem, args.category, False)
    
    elif args.command == 'stats':
        stats = manager.get_rule_stats()
        print(f"\nRule Statistics:")
        print(f"Total rules: {stats['total_rules']}")
        print(f"\nBy ecosystem:")
        for ecosystem, count in stats['by_ecosystem'].items():
            print(f"  {ecosystem}: {count}")
        print(f"\nBy severity:")
        for severity, count in stats['by_severity'].items():
            print(f"  {severity}: {count}")

if __name__ == "__main__":
    main()
