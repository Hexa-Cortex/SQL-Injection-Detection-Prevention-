"""
SQL Injection Detection Engine
Implements pattern-based and heuristic detection of SQL injection attempts
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple

class SQLInjectionDetector:
    def __init__(self):
        self.setup_logging()
        self.load_signatures()
        self.sql_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 
            'ALTER', 'EXEC', 'EXECUTE', 'UNION', 'DECLARE', 'CAST',
            'CONVERT', 'WAITFOR', 'DELAY', 'BENCHMARK'
        ]
        
    def setup_logging(self):
        """Configure logging for attack detection"""
        logging.basicConfig(
            filename='logs/attack_logs.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_signatures(self):
        """Load SQL injection signatures from file"""
        self.signatures = {
            'classic': [
                r"(\s|^)OR(\s|$)",
                r"(\s|^)AND(\s|$)",
                r"'(\s*)OR(\s*)'",
                r"'(\s*)=(\s*)'",
                r"1(\s*)=(\s*)1",
                r"1'1",
                r"admin'--",
                r"admin'#"
            ],
            'union': [
                r"UNION(\s+)ALL(\s+)SELECT",
                r"UNION(\s+)SELECT",
                r"\+UNION\+",
                r"UNION.*SELECT.*FROM"
            ],
            'comment': [
                r"--",
                r"#",
                r"/\*.*\*/",
                r";--",
                r"';--"
            ],
            'time_based': [
                r"SLEEP\(",
                r"BENCHMARK\(",
                r"WAITFOR(\s+)DELAY",
                r"pg_sleep\("
            ],
            'stacked': [
                r";\s*DROP",
                r";\s*DELETE",
                r";\s*INSERT",
                r";\s*UPDATE",
                r";\s*EXEC"
            ],
            'error_based': [
                r"CONVERT\(",
                r"CAST\(",
                r"@@version",
                r"@@servername",
                r"extractvalue\(",
                r"updatexml\("
            ],
            'boolean_blind': [
                r"(\s+)AND(\s+)\d+(\s*)=(\s*)\d+",
                r"(\s+)OR(\s+)\d+(\s*)=(\s*)\d+",
                r"'(\s+)AND(\s+)'",
                r"'(\s+)OR(\s+)'"
            ]
        }
    
    def detect(self, input_string: str) -> Tuple[bool, Dict]:
        """
        Main detection method
        Returns: (is_malicious, details_dict)
        """
        if not input_string:
            return False, {}
        
        input_upper = input_string.upper()
        
        # Check for multiple detection methods
        results = {
            'is_malicious': False,
            'confidence': 0.0,
            'detected_patterns': [],
            'attack_type': [],
            'risk_level': 'LOW',
            'input': input_string[:100],  # Limit logged input
            'timestamp': datetime.now().isoformat()
        }
        
        # Pattern-based detection
        pattern_score = self._pattern_detection(input_string, results)
        
        # Heuristic-based detection
        heuristic_score = self._heuristic_detection(input_upper, results)
        
        # SQL keyword density check
        keyword_score = self._keyword_density(input_upper, results)
        
        # Character anomaly detection
        anomaly_score = self._character_anomaly(input_string, results)
        
        # Calculate final confidence score
        total_score = pattern_score + heuristic_score + keyword_score + anomaly_score
        results['confidence'] = min(total_score / 4.0, 1.0)
        
        # Determine if malicious
        if results['confidence'] > 0.6:
            results['is_malicious'] = True
            results['risk_level'] = 'HIGH' if results['confidence'] > 0.8 else 'MEDIUM'
            self.log_attack(results)
        
        return results['is_malicious'], results
    
    def _pattern_detection(self, input_string: str, results: Dict) -> float:
        """Pattern-based detection using signatures"""
        score = 0.0
        input_upper = input_string.upper()
        
        for attack_type, patterns in self.signatures.items():
            for pattern in patterns:
                if re.search(pattern, input_upper, re.IGNORECASE):
                    results['detected_patterns'].append(pattern)
                    if attack_type not in results['attack_type']:
                        results['attack_type'].append(attack_type)
                    score += 0.3
        
        return min(score, 1.0)
    
    def _heuristic_detection(self, input_string: str, results: Dict) -> float:
        """Heuristic-based detection"""
        score = 0.0
        
        # Check for unbalanced quotes
        if input_string.count("'") % 2 != 0:
            results['detected_patterns'].append('unbalanced_quotes')
            score += 0.2
        
        # Check for multiple dashes (comment attempt)
        if '--' in input_string or input_string.count('-') > 2:
            results['detected_patterns'].append('comment_pattern')
            score += 0.3
        
        # Check for semicolons (statement termination)
        if ';' in input_string and any(keyword in input_string for keyword in self.sql_keywords):
            results['detected_patterns'].append('statement_stacking')
            score += 0.4
        
        # Check for multiple spaces (obfuscation attempt)
        if re.search(r'\s{3,}', input_string):
            results['detected_patterns'].append('space_obfuscation')
            score += 0.1
        
        return min(score, 1.0)
    
    def _keyword_density(self, input_string: str, results: Dict) -> float:
        """Calculate SQL keyword density"""
        keyword_count = sum(1 for keyword in self.sql_keywords if keyword in input_string)
        
        # Short strings with multiple keywords are suspicious
        if len(input_string) < 50 and keyword_count >= 2:
            results['detected_patterns'].append('high_keyword_density')
            return 0.4
        elif keyword_count >= 3:
            results['detected_patterns'].append('multiple_sql_keywords')
            return 0.3
        
        return 0.0
    
    def _character_anomaly(self, input_string: str, results: Dict) -> float:
        """Detect character-based anomalies"""
        score = 0.0
        
        # Check for hex encoding
        if re.search(r'0x[0-9a-fA-F]+', input_string):
            results['detected_patterns'].append('hex_encoding')
            score += 0.2
        
        # Check for char/ascii functions
        if re.search(r'(CHAR|ASCII|CHR)\s*\(', input_string, re.IGNORECASE):
            results['detected_patterns'].append('char_encoding')
            score += 0.3
        
        # Check for URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', input_string):
            results['detected_patterns'].append('url_encoding')
            score += 0.1
        
        return min(score, 1.0)
    
    def log_attack(self, results: Dict):
        """Log detected attack attempts"""
        self.logger.warning(f"SQL Injection Detected: {json.dumps(results)}")
        
        # Also save to JSON log file
        try:
            with open('logs/attack_logs.json', 'a') as f:
                json.dump(results, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write to JSON log: {e}")
    
    def analyze_query(self, query: str) -> Dict:
        """Detailed analysis of a query"""
        is_malicious, details = self.detect(query)
        
        analysis = {
            'query': query,
            'is_safe': not is_malicious,
            'risk_assessment': details,
            'recommendations': self._generate_recommendations(details)
        }
        
        return analysis
    
    def _generate_recommendations(self, details: Dict) -> List[str]:
        """Generate security recommendations based on detection results"""
        recommendations = []
        
        if details.get('is_malicious'):
            recommendations.append("Block this request immediately")
            recommendations.append("Use parameterized queries/prepared statements")
            
            if 'union' in details.get('attack_type', []):
                recommendations.append("Implement proper error handling to prevent information disclosure")
            
            if 'time_based' in details.get('attack_type', []):
                recommendations.append("Implement query timeout limits")
            
            if 'unbalanced_quotes' in details.get('detected_patterns', []):
                recommendations.append("Sanitize input by escaping special characters")
            
            recommendations.append("Log this attempt for security audit")
            recommendations.append("Consider implementing rate limiting")
        else:
            recommendations.append("Input appears safe, but always use parameterized queries")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    detector = SQLInjectionDetector()
    
    # Test cases
    test_inputs = [
        "admin",  # Safe
        "admin' OR '1'='1",  # Classic injection
        "1 UNION SELECT username, password FROM users--",  # Union-based
        "1; DROP TABLE users--",  # Stacked queries
        "1' AND SLEEP(5)--",  # Time-based blind
        "admin'--",  # Comment injection
    ]
    
    print("SQL Injection Detection Test Results")
    print("=" * 60)
    
    for test_input in test_inputs:
        is_malicious, details = detector.detect(test_input)
        print(f"\nInput: {test_input}")
        print(f"Malicious: {is_malicious}")
        print(f"Confidence: {details['confidence']:.2f}")
        print(f"Risk Level: {details['risk_level']}")
        print(f"Attack Types: {', '.join(details['attack_type']) if details['attack_type'] else 'None'}")
        print("-" * 60)
