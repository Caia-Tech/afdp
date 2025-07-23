#!/usr/bin/env python3
"""
Example: Monitor notarization results from Pulsar

This script demonstrates how to consume notarization results and status
updates from the AFDP Notary Service via Apache Pulsar.

Prerequisites:
- Apache Pulsar running on localhost:6650
- Python pulsar-client library: pip install pulsar-client
- AFDP Notary service publishing results

Usage:
    python monitor-results.py
    
Configuration:
    Set environment variables:
    - PULSAR_SERVICE_URL (default: pulsar://localhost:6650)
    - PULSAR_RESULTS_TOPIC (default: afdp.notary.results)
    - PULSAR_STATUS_TOPIC (default: afdp.notary.status)
    - PULSAR_ERRORS_TOPIC (default: afdp.notary.errors)
"""

import json
import os
import signal
import sys
from datetime import datetime
import pulsar

class NotaryMonitor:
    def __init__(self):
        self.service_url = os.getenv('PULSAR_SERVICE_URL', 'pulsar://localhost:6650')
        self.results_topic = os.getenv('PULSAR_RESULTS_TOPIC', 'persistent://afdp/default/afdp.notary.results')
        self.status_topic = os.getenv('PULSAR_STATUS_TOPIC', 'persistent://afdp/default/afdp.notary.status')
        self.errors_topic = os.getenv('PULSAR_ERRORS_TOPIC', 'persistent://afdp/default/afdp.notary.errors')
        
        self.client = None
        self.consumers = []
        self.running = True
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\n🛑 Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def format_timestamp(self, iso_string):
        """Format ISO timestamp for display"""
        try:
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return iso_string
    
    def handle_result_message(self, consumer, msg):
        """Handle notarization result messages"""
        try:
            data = json.loads(msg.data().decode('utf-8'))
            
            print("🎯 NOTARIZATION RESULT")
            print("=" * 40)
            print(f"Event ID: {data.get('event_id', 'Unknown')}")
            print(f"Workflow ID: {data.get('workflow_id', 'Unknown')}")
            print(f"Workflow Type: {data.get('workflow_type', 'Unknown')}")
            print(f"Timestamp: {self.format_timestamp(data.get('timestamp', ''))}")
            print(f"Success: {'✅ YES' if data.get('success', False) else '❌ NO'}")
            
            if data.get('error'):
                print(f"Error: {data['error']}")
            
            if data.get('receipt'):
                receipt = data['receipt']
                print(f"Receipt:")
                print(f"  Evidence Hash: {receipt.get('evidence_package_hash', 'N/A')}")
                print(f"  Rekor Log ID: {receipt.get('rekor_log_id', 'N/A')}")
                print(f"  Log Index: {receipt.get('log_index', 'N/A')}")
                print(f"  Integration Time: {receipt.get('integrated_time', 'N/A')}")
            
            print(f"Processing Duration: {data.get('processing_duration_ms', 0)}ms")
            
            if data.get('trace_id'):
                print(f"Trace ID: {data['trace_id']}")
            
            print()
            
            consumer.acknowledge(msg)
            
        except Exception as e:
            print(f"❌ Error processing result message: {e}")
            consumer.negative_acknowledge(msg)
    
    def handle_status_message(self, consumer, msg):
        """Handle workflow status messages"""
        try:
            data = json.loads(msg.data().decode('utf-8'))
            
            status_icons = {
                'received': '📥',
                'started': '🚀',
                'pending_approval': '⏳',
                'processing': '⚙️',
                'waiting': '⏸️',
                'completed': '✅',
                'failed': '❌',
                'cancelled': '🚫',
                'timeout': '⏰'
            }
            
            status = data.get('status', 'unknown')
            icon = status_icons.get(status, '❓')
            
            print(f"{icon} STATUS UPDATE")
            print("=" * 30)
            print(f"Event ID: {data.get('event_id', 'Unknown')}")
            print(f"Workflow ID: {data.get('workflow_id', 'Unknown')}")
            print(f"Status: {status.upper()}")
            print(f"Message: {data.get('message', 'No message')}")
            print(f"Timestamp: {self.format_timestamp(data.get('timestamp', ''))}")
            
            if data.get('progress'):
                progress = data['progress']
                print(f"Progress: {progress.get('percentage', 0)}% ({progress.get('completed_steps', 0)}/{progress.get('total_steps', 0)})")
                if progress.get('eta_seconds'):
                    print(f"ETA: {progress['eta_seconds']}s")
            
            if data.get('trace_id'):
                print(f"Trace ID: {data['trace_id']}")
            
            print()
            
            consumer.acknowledge(msg)
            
        except Exception as e:
            print(f"❌ Error processing status message: {e}")
            consumer.negative_acknowledge(msg)
    
    def handle_error_message(self, consumer, msg):
        """Handle error messages"""
        try:
            data = json.loads(msg.data().decode('utf-8'))
            
            error_icons = {
                'validation': '📝',
                'authentication': '🔐',
                'workflow': '⚙️',
                'signing': '✍️',
                'transparency': '📋',
                'network': '🌐',
                'configuration': '⚙️',
                'internal': '🔧',
                'timeout': '⏰',
                'resource': '💾'
            }
            
            error_type = data.get('error_type', 'unknown')
            icon = error_icons.get(error_type, '❌')
            
            print(f"{icon} ERROR EVENT")
            print("=" * 30)
            print(f"Event ID: {data.get('event_id', 'Unknown')}")
            print(f"Workflow ID: {data.get('workflow_id', 'N/A')}")
            print(f"Error Type: {error_type.upper()}")
            print(f"Message: {data.get('message', 'No message')}")
            print(f"Timestamp: {self.format_timestamp(data.get('timestamp', ''))}")
            print(f"Retry Count: {data.get('retry_count', 0)}")
            
            if data.get('details'):
                print("Details:")
                for key, value in data['details'].items():
                    print(f"  {key}: {value}")
            
            if data.get('trace_id'):
                print(f"Trace ID: {data['trace_id']}")
            
            print()
            
            consumer.acknowledge(msg)
            
        except Exception as e:
            print(f"❌ Error processing error message: {e}")
            consumer.negative_acknowledge(msg)
    
    def start_monitoring(self):
        """Start monitoring all topics"""
        print("🔍 AFDP Notary Service - Results Monitor")
        print("=" * 50)
        print(f"Service URL: {self.service_url}")
        print(f"Results Topic: {self.results_topic}")
        print(f"Status Topic: {self.status_topic}")
        print(f"Errors Topic: {self.errors_topic}")
        print()
        
        try:
            # Create Pulsar client
            print("📡 Connecting to Pulsar...")
            self.client = pulsar.Client(self.service_url)
            
            # Create consumers
            results_consumer = self.client.subscribe(
                self.results_topic,
                subscription_name="afdp-monitor-results",
                consumer_type=pulsar.ConsumerType.Shared,
                message_listener=self.handle_result_message,
                initial_position=pulsar.InitialPosition.Latest
            )
            self.consumers.append(results_consumer)
            
            status_consumer = self.client.subscribe(
                self.status_topic,
                subscription_name="afdp-monitor-status",
                consumer_type=pulsar.ConsumerType.Shared,
                message_listener=self.handle_status_message,
                initial_position=pulsar.InitialPosition.Latest
            )
            self.consumers.append(status_consumer)
            
            errors_consumer = self.client.subscribe(
                self.errors_topic,
                subscription_name="afdp-monitor-errors",
                consumer_type=pulsar.ConsumerType.Shared,
                message_listener=self.handle_error_message,
                initial_position=pulsar.InitialPosition.Latest
            )
            self.consumers.append(errors_consumer)
            
            print("✅ Connected to Pulsar successfully")
            print("👂 Listening for messages... (Press Ctrl+C to stop)")
            print()
            
            # Keep the main thread alive
            while self.running:
                import time
                time.sleep(1)
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return 1
        
        finally:
            self.cleanup()
        
        return 0
    
    def cleanup(self):
        """Clean up resources"""
        print("🧹 Cleaning up...")
        
        for consumer in self.consumers:
            try:
                consumer.close()
            except:
                pass
        
        if self.client:
            try:
                self.client.close()
            except:
                pass
        
        print("✅ Cleanup completed")

def main():
    monitor = NotaryMonitor()
    return monitor.start_monitoring()

if __name__ == "__main__":
    exit(main())