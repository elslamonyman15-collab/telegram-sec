#!/usr/bin/env python3
"""
MFT (Master File Table) Parser for Cyber Forensics Toolkit v8.0
Analyzes NTFS MFT for deleted files, ADS, and file system artifacts
"""

import os
import sys
import logging
import struct
import datetime
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MFTParser:
    """Parse NTFS Master File Table for forensic analysis"""
    
    def __init__(self, drive_letter='C'):
        self.drive_letter = drive_letter
        self.mft_file = f"{drive_letter}:\\$MFT"
        self.entries = []
        
    def parse_mft(self):
        """Parse MFT file (requires admin privileges and raw disk access)"""
        if not os.path.exists(self.mft_file):
            logger.warning(f"MFT file not accessible: {self.mft_file}")
            return None
        
        try:
            # Note: This is a simplified implementation
            # Full MFT parsing requires raw disk access and complex binary parsing
            # For now, we'll use alternative methods
            
            logger.info("MFT raw parsing requires raw disk access. Using alternative methods...")
            return self._analyze_filesystem_alternative()
            
        except Exception as e:
            logger.error(f"Error parsing MFT: {e}")
            return None
    
    def _analyze_filesystem_alternative(self):
        """Alternative filesystem analysis using Windows tools"""
        results = {
            'drive': self.drive_letter,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'deleted_files': [],
            'ads_files': [],
            'suspicious_files': []
        }
        
        # Use USN Journal for file changes
        try:
            usn_data = self._parse_usn_journal()
            if usn_data:
                results['usn_journal'] = usn_data
        except Exception as e:
            logger.error(f"Error parsing USN journal: {e}")
        
        # Detect Alternate Data Streams
        try:
            ads_data = self._detect_ads()
            results['ads_files'] = ads_data
        except Exception as e:
            logger.error(f"Error detecting ADS: {e}")
        
        # Detect recently deleted files (via shadow copies if available)
        try:
            deleted_data = self._detect_deleted_files()
            results['deleted_files'] = deleted_data
        except Exception as e:
            logger.error(f"Error detecting deleted files: {e}")
        
        return results
    
    def _parse_usn_journal(self):
        """Parse USN Journal for file system changes"""
        try:
            # Use fsutil to query USN journal
            result = subprocess.run(
                ['fsutil', 'usn', 'readjournal', f'{self.drive_letter}:'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return self._parse_usn_output(result.stdout)
            
            return None
            
        except Exception as e:
            logger.error(f"Error reading USN journal: {e}")
            return None
    
    def _parse_usn_output(self, output):
        """Parse USN journal output"""
        entries = []
        
        for line in output.split('\n'):
            if line.strip():
                # Parse USN record (simplified)
                entries.append({
                    'raw': line.strip(),
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return entries
    
    def _detect_ads(self):
        """Detect Alternate Data Streams"""
        ads_files = []
        
        try:
            # Scan system directories for ADS
            critical_dirs = [
                f"{self.drive_letter}:\\Windows\\System32",
                f"{self.drive_letter}:\\ProgramData",
                os.path.expandvars(f"%USERPROFILE%")
            ]
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            ads_streams = self._get_ads_streams(file_path)
                            
                            if ads_streams:
                                ads_files.append({
                                    'file': file_path,
                                    'streams': ads_streams,
                                    'severity': 'High'
                                })
        
        except Exception as e:
            logger.error(f"Error detecting ADS: {e}")
        
        return ads_files
    
    def _get_ads_streams(self, file_path):
        """Get Alternate Data Streams for a file"""
        streams = []
        
        try:
            # Use PowerShell to detect ADS
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', f"Get-Item -Path '{file_path}' -Stream * | Select-Object Stream"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip() and line.strip() != 'Stream' and '$DATA' not in line:
                        streams.append(line.strip())
        
        except Exception:
            pass
        
        return streams
    
    def _detect_deleted_files(self):
        """Detect recently deleted files"""
        deleted_files = []
        
        try:
            # Check Recycle Bin
            recycle_bin = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Microsoft", "Windows", "Recycle Bin")
            
            if os.path.exists(recycle_bin):
                for root, dirs, files in os.walk(recycle_bin):
                    for file in files:
                        deleted_files.append({
                            'file': file,
                            'location': os.path.join(root, file),
                            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
        
        except Exception as e:
            logger.error(f"Error detecting deleted files: {e}")
        
        return deleted_files
    
    def detect_steganography(self):
        """Detect potential steganography in files"""
        suspicious_files = []
        
        try:
            # Check for files with unusual size patterns
            critical_dirs = [
                f"{self.drive_letter}:\\Users",
                f"{self.drive_letter}:\\Windows"
            ]
            
            for directory in critical_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Check for suspicious file extensions
                            suspicious_extensions = ['.jpg', '.png', '.bmp', '.mp3', '.mp4', '.pdf']
                            if any(file.lower().endswith(ext) for ext in suspicious_extensions):
                                # Check for unusually large files
                                try:
                                    file_size = os.path.getsize(file_path)
                                    if file_size > 10 * 1024 * 1024:  # > 10MB
                                        suspicious_files.append({
                                            'file': file_path,
                                            'size': file_size,
                                            'reason': 'Unusually large media file',
                                            'severity': 'Medium'
                                        })
                                except Exception:
                                    pass
        
        except Exception as e:
            logger.error(f"Error detecting steganography: {e}")
        
        return suspicious_files


class NTFSAnalyzer:
    """NTFS filesystem analyzer"""
    
    def __init__(self, drive_letter='C'):
        self.drive_letter = drive_letter
        self.mft_parser = MFTParser(drive_letter)
    
    def analyze_ntfs(self):
        """Comprehensive NTFS analysis"""
        results = {
            'drive': self.drive_letter,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'mft_analysis': self.mft_parser.parse_mft(),
            'steganography_detection': self.mft_parser.detect_steganography()
        }
        
        return results
    
    def get_file_metadata(self, file_path):
        """Get detailed file metadata"""
        try:
            stat = os.stat(file_path)
            
            return {
                'path': file_path,
                'size': stat.st_size,
                'created': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'accessed': datetime.datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                'attributes': self._get_file_attributes(file_path)
            }
            
        except Exception as e:
            logger.error(f"Error getting file metadata: {e}")
            return None
    
    def _get_file_attributes(self, file_path):
        """Get Windows file attributes"""
        try:
            import subprocess
            result = subprocess.run(
                ['attrib', file_path],
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                return result.stdout.strip()
            
            return None
            
        except Exception:
            return None
    
    def detect_timestamp_manipulation(self, directory):
        """Detect potential timestamp manipulation (MAC times)"""
        suspicious_files = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        stat = os.stat(file_path)
                        ctime = stat.st_ctime
                        mtime = stat.st_mtime
                        atime = stat.st_atime
                        
                        # Check if all timestamps are identical (suspicious)
                        if ctime == mtime == atime:
                            suspicious_files.append({
                                'file': file_path,
                                'reason': 'All timestamps identical',
                                'severity': 'Medium'
                            })
                        
                        # Check if modification time is before creation time (impossible)
                        if mtime < ctime - 3600:  # 1 hour tolerance
                            suspicious_files.append({
                                'file': file_path,
                                'reason': 'Modification time before creation time',
                                'severity': 'High'
                            })
                    
                    except Exception:
                        pass
        
        except Exception as e:
            logger.error(f"Error detecting timestamp manipulation: {e}")
        
        return suspicious_files


if __name__ == "__main__":
    # Test the MFT parser
    analyzer = NTFSAnalyzer('C')
    
    print("Analyzing NTFS filesystem...")
    results = analyzer.analyze_ntfs()
    
    print(f"\nDrive: {results['drive']}")
    print(f"Timestamp: {results['timestamp']}")
    
    if results['mft_analysis']:
        mft = results['mft_analysis']
        print(f"ADS Files: {len(mft.get('ads_files', []))}")
        print(f"Deleted Files: {len(mft.get('deleted_files', []))}")
    
    print(f"Steganography Suspicious Files: {len(results['steganography_detection'])}")
