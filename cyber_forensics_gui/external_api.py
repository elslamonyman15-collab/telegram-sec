#!/usr/bin/env python3
"""
External API Integration Module for Cyber Forensics Toolkit v8.0
Integrates with AbuseIPDB, VirusTotal, and other threat intelligence APIs
"""

import os
import json
import logging
import requests
import hashlib
import time
from datetime import datetime, timedelta
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelligenceAPI:
    """Base class for threat intelligence API integrations"""
    
    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.join(
            os.path.expanduser("~"),
            ".cyber_forensics_api_config.json"
        )
        self.config = self.load_config()
        self.cache = defaultdict(dict)
        self.cache_duration = 3600  # 1 hour cache
        
    def load_config(self):
        """Load API configuration"""
        default_config = {
            "abuseipdb_api_key": "",
            "virustotal_api_key": "",
            "enable_caching": True,
            "rate_limit_per_minute": 60
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                return {**default_config, **config}
            except Exception as e:
                logger.error(f"Error loading API config: {e}")
        
        return default_config
    
    def save_config(self):
        """Save API configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info("API configuration saved")
        except Exception as e:
            logger.error(f"Error saving API config: {e}")
    
    def _is_cached(self, api_name, key):
        """Check if result is cached and still valid"""
        if not self.config.get("enable_caching", True):
            return False
        
        if api_name in self.cache and key in self.cache[api_name]:
            cached_time = self.cache[api_name][key]['timestamp']
            if time.time() - cached_time < self.cache_duration:
                return True
        
        return False
    
    def _get_cached(self, api_name, key):
        """Get cached result"""
        return self.cache[api_name][key]['data']
    
    def _set_cache(self, api_name, key, data):
        """Set cached result"""
        self.cache[api_name][key] = {
            'data': data,
            'timestamp': time.time()
        }


class AbuseIPDB(ThreatIntelligenceAPI):
    """AbuseIPDB API integration for IP reputation checking"""
    
    def __init__(self, config_file=None):
        super().__init__(config_file)
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    def check_ip(self, ip_address):
        """Check IP reputation using AbuseIPDB"""
        if not self.config.get("abuseipdb_api_key"):
            logger.warning("AbuseIPDB API key not configured")
            return None
        
        # Check cache
        if self._is_cached("abuseipdb", ip_address):
            return self._get_cached("abuseipdb", ip_address)
        
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb_api_key']
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_abuseipdb_response(data)
                self._set_cache("abuseipdb", ip_address, result)
                return result
            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking IP with AbuseIPDB: {e}")
            return None
    
    def _parse_abuseipdb_response(self, data):
        """Parse AbuseIPDB API response"""
        if 'data' not in data:
            return None
        
        ip_data = data['data']
        
        return {
            'ip_address': ip_data.get('ipAddress'),
            'abuse_confidence_score': ip_data.get('abuseConfidenceScore', 0),
            'country_code': ip_data.get('countryCode'),
            'isp': ip_data.get('isp'),
            'domain': ip_data.get('domain'),
            'total_reports': ip_data.get('totalReports', 0),
            'last_reported_at': ip_data.get('lastReportedAt'),
            'is_whitelisted': ip_data.get('isWhitelisted', False),
            'is_tor': ip_data.get('isTor', False),
            'reports': ip_data.get('reports', [])
        }
    
    def report_ip(self, ip_address, categories, comment):
        """Report malicious IP to AbuseIPDB"""
        if not self.config.get("abuseipdb_api_key"):
            return False
        
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.config['abuseipdb_api_key']
            }
            
            data = {
                'ip': ip_address,
                'categories': categories,
                'comment': comment
            }
            
            response = requests.post(
                f"{self.base_url}/report",
                headers=headers,
                json=data,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Error reporting IP to AbuseIPDB: {e}")
            return False


class VirusTotal(ThreatIntelligenceAPI):
    """VirusTotal API integration for file and URL analysis"""
    
    def __init__(self, config_file=None):
        super().__init__(config_file)
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def scan_file(self, file_path):
        """Scan file using VirusTotal"""
        if not self.config.get("virustotal_api_key"):
            logger.warning("VirusTotal API key not configured")
            return None
        
        # Check cache
        file_hash = self._calculate_file_hash(file_path)
        if self._is_cached("virustotal", file_hash):
            return self._get_cached("virustotal", file_hash)
        
        try:
            # First, check if file is already analyzed
            file_info = self.get_file_info(file_hash)
            if file_info:
                self._set_cache("virustotal", file_hash, file_info)
                return file_info
            
            # If not, upload for scanning
            return self._upload_file(file_path)
            
        except Exception as e:
            logger.error(f"Error scanning file with VirusTotal: {e}")
            return None
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    def get_file_info(self, file_hash):
        """Get file analysis from VirusTotal"""
        try:
            headers = {
                'x-apikey': self.config['virustotal_api_key']
            }
            
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_virustotal_response(data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting file info from VirusTotal: {e}")
            return None
    
    def _upload_file(self, file_path):
        """Upload file to VirusTotal for scanning"""
        try:
            headers = {
                'x-apikey': self.config['virustotal_api_key']
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=headers,
                    files=files,
                    timeout=60
                )
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                
                # Wait for analysis to complete
                return self._get_analysis_result(analysis_id)
            
            return None
            
        except Exception as e:
            logger.error(f"Error uploading file to VirusTotal: {e}")
            return None
    
    def _get_analysis_result(self, analysis_id):
        """Get analysis result from VirusTotal"""
        try:
            headers = {
                'x-apikey': self.config['virustotal_api_key']
            }
            
            # Poll for results
            for _ in range(30):  # Wait up to 30 seconds
                response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get('data', {}).get('attributes', {}).get('status')
                    
                    if status == 'completed':
                        return self._parse_virustotal_response(data)
                
                time.sleep(1)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting analysis result: {e}")
            return None
    
    def _parse_virustotal_response(self, data):
        """Parse VirusTotal API response"""
        if 'data' not in data:
            return None
        
        attributes = data['data'].get('attributes', {})
        
        return {
            'sha256': attributes.get('sha256'),
            'md5': attributes.get('md5'),
            'sha1': attributes.get('sha1'),
            'positives': attributes.get('last_analysis_stats', {}).get('malicious', 0),
            'total': attributes.get('last_analysis_stats', {}).get('harmless', 0) + 
                     attributes.get('last_analysis_stats', {}).get('malicious', 0) +
                     attributes.get('last_analysis_stats', {}).get('suspicious', 0),
            'scan_date': attributes.get('last_analysis_date'),
            'reputation': attributes.get('reputation', 0),
            'names': attributes.get('names', []),
            'type_description': attributes.get('type_description')
        }


class ThreatIntelligenceManager:
    """Manages multiple threat intelligence APIs"""
    
    def __init__(self, config_file=None):
        self.abuseipdb = AbuseIPDB(config_file)
        self.virustotal = VirusTotal(config_file)
        
    def check_ip_reputation(self, ip_address):
        """Check IP reputation across multiple sources"""
        results = {
            'ip_address': ip_address,
            'abuseipdb': None,
            'virustotal': None,
            'overall_score': 0,
            'is_malicious': False
        }
        
        # Check AbuseIPDB
        abuse_result = self.abuseipdb.check_ip(ip_address)
        if abuse_result:
            results['abuseipdb'] = abuse_result
            results['overall_score'] += abuse_result.get('abuse_confidence_score', 0)
        
        # Determine if malicious
        if results['overall_score'] > 50:
            results['is_malicious'] = True
        
        return results
    
    def scan_file(self, file_path):
        """Scan file across multiple sources"""
        results = {
            'file_path': file_path,
            'virustotal': None,
            'is_malicious': False
        }
        
        # Scan with VirusTotal
        vt_result = self.virustotal.scan_file(file_path)
        if vt_result:
            results['virustotal'] = vt_result
            if vt_result.get('positives', 0) > 0:
                results['is_malicious'] = True
        
        return results


if __name__ == "__main__":
    # Test the API integrations
    manager = ThreatIntelligenceManager()
    
    print("Testing IP reputation check...")
    ip_result = manager.check_ip_reputation("8.8.8.8")
    print(f"Result: {ip_result}")
    
    print("\nNote: Configure API keys in ~/.cyber_forensics_api_config.json to use full functionality")
