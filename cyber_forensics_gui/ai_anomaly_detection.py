#!/usr/bin/env python3
"""
AI-Powered Anomaly Detection Module for Cyber Forensics Toolkit v8.0
Uses machine learning to detect behavioral anomalies and threats
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import pickle

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """AI-powered anomaly detection using machine learning"""
    
    def __init__(self, model_file=None):
        self.model_file = model_file or os.path.join(
            os.path.expanduser("~"), 
            ".cyber_forensics_models.pkl"
        )
        self.models = {}
        self.baselines = {}
        self.load_models()
        
    def load_models(self):
        """Load trained models from file"""
        if os.path.exists(self.model_file):
            try:
                with open(self.model_file, 'rb') as f:
                    self.models = pickle.load(f)
                logger.info("AI models loaded successfully")
            except Exception as e:
                logger.error(f"Error loading models: {e}")
                self.models = {}
        else:
            logger.info("No pre-trained models found, will use statistical methods")
    
    def save_models(self):
        """Save trained models to file"""
        try:
            with open(self.model_file, 'wb') as f:
                pickle.dump(self.models, f)
            logger.info("AI models saved successfully")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def initialize_baseline(self, data):
        """Initialize baseline behavior from historical data"""
        logger.info("Initializing behavioral baseline...")
        
        # Process baseline statistics
        if 'processes' in data:
            self.baselines['processes'] = {
                'count_mean': np.mean([len(p) for p in data['processes']]),
                'count_std': np.std([len(p) for p in data['processes']]),
                'common_processes': self._get_common_processes(data['processes'])
            }
        
        if 'network' in data:
            self.baselines['network'] = {
                'connection_count_mean': np.mean([len(c) for c in data['network']]),
                'connection_count_std': np.std([len(c) for c in data['network']]),
                'common_ports': self._get_common_ports(data['network'])
            }
        
        logger.info(f"Baseline initialized with {len(self.baselines)} categories")
    
    def _get_common_processes(self, process_list):
        """Get most common processes from baseline"""
        process_counts = defaultdict(int)
        for processes in process_list:
            for proc in processes:
                process_counts[proc] += 1
        return dict(sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:20])
    
    def _get_common_ports(self, network_list):
        """Get most common ports from baseline"""
        port_counts = defaultdict(int)
        for connections in network_list:
            for conn in connections:
                port = conn.split(':')[-1] if ':' in conn else ''
                if port:
                    port_counts[port] += 1
        return dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:20])
    
    def detect_process_anomaly(self, current_processes):
        """Detect anomalies in process behavior"""
        anomalies = []
        
        if 'processes' not in self.baselines:
            return anomalies
        
        baseline = self.baselines['processes']
        process_count = len(current_processes)
        
        # Statistical anomaly detection using Z-score
        if baseline['count_std'] > 0:
            z_score = abs((process_count - baseline['count_mean']) / baseline['count_std'])
            if z_score > 3:  # 3 sigma threshold
                anomalies.append({
                    'type': 'process_count_anomaly',
                    'severity': 'High' if z_score > 5 else 'Medium',
                    'description': f"Unusual process count: {process_count} (baseline: {baseline['count_mean']:.1f} ± {baseline['count_std']:.1f})",
                    'z_score': z_score
                })
        
        # Check for rare processes
        rare_processes = []
        for proc in current_processes:
            if proc not in baseline['common_processes']:
                rare_processes.append(proc)
        
        if rare_processes:
            anomalies.append({
                'type': 'rare_process',
                'severity': 'Medium',
                'description': f"Rare or new processes detected: {', '.join(rare_processes[:5])}",
                'processes': rare_processes
            })
        
        return anomalies
    
    def detect_network_anomaly(self, current_connections):
        """Detect anomalies in network behavior"""
        anomalies = []
        
        if 'network' not in self.baselines:
            return anomalies
        
        baseline = self.baselines['network']
        connection_count = len(current_connections)
        
        # Statistical anomaly detection
        if baseline['connection_count_std'] > 0:
            z_score = abs((connection_count - baseline['connection_count_mean']) / baseline['connection_count_std'])
            if z_score > 3:
                anomalies.append({
                    'type': 'network_count_anomaly',
                    'severity': 'High' if z_score > 5 else 'Medium',
                    'description': f"Unusual connection count: {connection_count} (baseline: {baseline['connection_count_mean']:.1f} ± {baseline['connection_count_std']:.1f})",
                    'z_score': z_score
                })
        
        # Check for rare ports
        rare_ports = []
        for conn in current_connections:
            port = conn.split(':')[-1] if ':' in conn else ''
            if port and port not in baseline['common_ports']:
                rare_ports.append(port)
        
        if rare_ports:
            anomalies.append({
                'type': 'rare_port',
                'severity': 'Medium',
                'description': f"Connections to rare ports detected: {', '.join(set(rare_ports[:5]))}",
                'ports': list(set(rare_ports))
            })
        
        return anomalies
    
    def detect_temporal_anomaly(self, activity_data):
        """Detect temporal anomalies in activity patterns"""
        anomalies = []
        
        # Group activity by hour
        hourly_activity = defaultdict(list)
        for timestamp, count in activity_data:
            hour = timestamp.hour
            hourly_activity[hour].append(count)
        
        # Calculate hourly averages
        hourly_avg = {hour: np.mean(counts) for hour, counts in hourly_activity.items()}
        
        # Detect unusual activity for current hour
        current_hour = datetime.now().hour
        if current_hour in hourly_avg:
            current_activity = activity_data[-1][1] if activity_data else 0
            historical_avg = hourly_avg[current_hour]
            
            if historical_avg > 0:
                deviation = abs(current_activity - historical_avg) / historical_avg
                if deviation > 2.0:  # 200% deviation
                    anomalies.append({
                        'type': 'temporal_anomaly',
                        'severity': 'High' if deviation > 5.0 else 'Medium',
                        'description': f"Unusual activity for hour {current_hour}: {current_activity} (avg: {historical_avg:.1f})",
                        'deviation': deviation
                    })
        
        return anomalies
    
    def detect_sequence_anomaly(self, event_sequence):
        """Detect anomalous event sequences"""
        anomalies = []
        
        # Check for rapid repeated events
        if len(event_sequence) > 10:
            recent_events = event_sequence[-10:]
            event_types = set(event['type'] for event in recent_events)
            
            # Check for same event type repeated rapidly
            for event_type in event_types:
                count = sum(1 for e in recent_events if e['type'] == event_type)
                if count >= 7:  # 7 out of 10 events are the same
                    anomalies.append({
                        'type': 'sequence_anomaly',
                        'severity': 'High',
                        'description': f"Rapid repeated event type: {event_type} ({count} times in recent events)",
                        'event_type': event_type,
                        'count': count
                    })
        
        return anomalies
    
    def train_model(self, training_data):
        """Train ML model on historical data (simplified version)"""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            
            # Prepare features
            features = []
            for data_point in training_data:
                feature_vector = [
                    data_point.get('process_count', 0),
                    data_point.get('connection_count', 0),
                    data_point.get('file_changes', 0),
                    data_point.get('registry_changes', 0),
                    data_point.get('hour_of_day', datetime.now().hour)
                ]
                features.append(feature_vector)
            
            if len(features) > 10:
                # Scale features
                scaler = StandardScaler()
                scaled_features = scaler.fit_transform(features)
                
                # Train Isolation Forest
                model = IsolationForest(contamination=0.1, random_state=42)
                model.fit(scaled_features)
                
                self.models['isolation_forest'] = {
                    'model': model,
                    'scaler': scaler
                }
                
                logger.info("ML model trained successfully")
                self.save_models()
                
        except ImportError:
            logger.warning("scikit-learn not available, using statistical methods only")
        except Exception as e:
            logger.error(f"Error training model: {e}")
    
    def predict_anomaly(self, current_data):
        """Predict if current data is anomalous using trained model"""
        if 'isolation_forest' not in self.models:
            # Fall back to statistical methods
            return []
        
        try:
            model_data = self.models['isolation_forest']
            model = model_data['model']
            scaler = model_data['scaler']
            
            # Prepare feature vector
            feature_vector = [
                current_data.get('process_count', 0),
                current_data.get('connection_count', 0),
                current_data.get('file_changes', 0),
                current_data.get('registry_changes', 0),
                current_data.get('hour_of_day', datetime.now().hour)
            ]
            
            # Scale and predict
            scaled_features = scaler.transform([feature_vector])
            prediction = model.predict(scaled_features)[0]
            
            if prediction == -1:  # Anomaly detected
                return [{
                    'type': 'ml_anomaly',
                    'severity': 'High',
                    'description': "Machine learning model detected anomalous behavior pattern",
                    'features': feature_vector
                }]
            
            return []
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return []


class BehavioralBaseline:
    """Maintains and updates behavioral baseline"""
    
    def __init__(self, max_history=1000):
        self.max_history = max_history
        self.history = defaultdict(lambda: deque(maxlen=max_history))
        
    def add_observation(self, category, value):
        """Add observation to history"""
        self.history[category].append({
            'value': value,
            'timestamp': datetime.now()
        })
    
    def get_baseline_stats(self, category):
        """Get statistical baseline for category"""
        if category not in self.history or len(self.history[category]) < 10:
            return None
        
        values = [obs['value'] for obs in self.history[category]]
        return {
            'mean': np.mean(values),
            'std': np.std(values),
            'min': np.min(values),
            'max': np.max(values),
            'median': np.median(values),
            'count': len(values)
        }
    
    def is_anomalous(self, category, value, threshold=3):
        """Check if value is anomalous compared to baseline"""
        stats = self.get_baseline_stats(category)
        if not stats or stats['std'] == 0:
            return False
        
        z_score = abs((value - stats['mean']) / stats['std'])
        return z_score > threshold


if __name__ == "__main__":
    # Test the anomaly detector
    detector = AnomalyDetector()
    
    # Simulate some data
    test_processes = ['explorer.exe', 'chrome.exe', 'svchost.exe'] * 10
    test_connections = ['192.168.1.1:443', '8.8.8.8:53'] * 15
    
    print("Testing process anomaly detection...")
    process_anomalies = detector.detect_process_anomaly(test_processes)
    for anomaly in process_anomalies:
        print(f"  {anomaly}")
    
    print("\nTesting network anomaly detection...")
    network_anomalies = detector.detect_network_anomaly(test_connections)
    for anomaly in network_anomalies:
        print(f"  {anomaly}")
