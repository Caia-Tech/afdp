#!/usr/bin/env python3
"""
Pulsar Event Publisher for AFDP Notary Service Testing

This script publishes realistic events to Pulsar topics to test the notary service's
event processing capabilities. It supports:

- Publishing all sample evidence packages as Pulsar events
- Configurable event rates and patterns
- Different event types and priorities
- Distributed tracing integration
- Comprehensive event metadata
"""

import asyncio
import json
import uuid
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import time
import random

try:
    import pulsar
except ImportError:
    print("⚠️  Apache Pulsar Python client not found. Please install it:")
    print("   pip install pulsar-client")
    exit(1)


@dataclass
class EventMetrics:
    """Metrics for published events"""
    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0
    avg_publish_time_ms: float = 0.0
    events_per_second: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0


class PulsarEventPublisher:
    """High-performance event publisher for testing Pulsar consumer"""
    
    def __init__(self, service_url: str = "pulsar://localhost:6650"):
        self.service_url = service_url
        self.client: Optional[pulsar.Client] = None
        self.producer: Optional[pulsar.Producer] = None
        self.logger = self._setup_logging()
        self.metrics = EventMetrics(start_time=time.time())
        
    def _setup_logging(self) -> logging.Logger:
        """Configure structured JSON logging"""
        logger = logging.getLogger("pulsar-event-publisher")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"component": "pulsar-publisher", "message": %(message)s}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    async def __aenter__(self):
        """Async context manager entry"""
        try:
            self.client = pulsar.Client(
                self.service_url,
                operation_timeout_seconds=30,
                connection_timeout_seconds=10,
                log_conf_file_path=None,  # Disable Pulsar's internal logging
            )
            
            self.producer = self.client.create_producer(
                topic="persistent://public/default/afdp-evidence",
                send_timeout_millis=30000,
                block_if_queue_full=True,
                batching_enabled=True,
                batch_size=100,
                max_pending_messages=1000,
                compression_type=pulsar.CompressionType.LZ4,
            )
            
            self.logger.info(f'"action": "pulsar_connected", "service_url": "{self.service_url}"')
            return self
            
        except Exception as e:
            self.logger.error(f'"action": "pulsar_connection_failed", "error": "{str(e)}"')
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        try:
            if self.producer:
                self.producer.flush()
                self.producer.close()
            if self.client:
                self.client.close()
                
            self.metrics.end_time = time.time()
            duration = self.metrics.end_time - self.metrics.start_time
            self.metrics.events_per_second = self.metrics.total_events / duration if duration > 0 else 0
            
            self.logger.info(
                f'"action": "pulsar_disconnected", "total_events": {self.metrics.total_events}, '
                f'"duration_seconds": {duration:.2f}, "events_per_second": {self.metrics.events_per_second:.2f}'
            )
            
        except Exception as e:
            self.logger.error(f'"action": "pulsar_disconnect_error", "error": "{str(e)}"')
    
    def create_pipeline_event(self, evidence_data: Dict, event_id: str = None) -> Dict:
        """Convert evidence package to Pulsar pipeline event format"""
        if event_id is None:
            event_id = str(uuid.uuid4())
        
        # Determine event type based on evidence type
        event_type_mapping = {
            "ai.model.deployment": "model_deployment",
            "security.vulnerability.scan": "compliance",
            "security.compliance.scan": "compliance",
            "financial.algorithm.deployment": "model_deployment",
            "financial.model.validation": "compliance",
            "healthcare.ai.deployment": "model_deployment",
            "pharma.ai.model.validation": "compliance",
            "supply_chain.provenance.verification": "compliance",
            "supply_chain.cold_chain.validation": "compliance",
        }
        
        evidence_event_type = evidence_data.get("event_type", "custom")
        pulsar_event_type = event_type_mapping.get(evidence_event_type, "custom")
        
        # Create event-specific data based on type
        event_specific_data = {}
        if pulsar_event_type == "model_deployment":
            model_id = evidence_data.get("metadata", {}).get("model_id", "unknown-model")
            event_specific_data = {
                "model_deployment": {
                    "model_id": model_id,
                    "version": evidence_data.get("metadata", {}).get("version", "1.0.0"),
                    "environment": evidence_data.get("metadata", {}).get("deployment_environment", "production"),
                    "strategy": evidence_data.get("metadata", {}).get("deployment_strategy", "rolling"),
                    "previous_version": evidence_data.get("metadata", {}).get("previous_version")
                }
            }
        elif pulsar_event_type == "compliance":
            event_specific_data = {
                "compliance": {
                    "scan_type": evidence_data.get("metadata", {}).get("scan_type", "unknown"),
                    "compliance_framework": evidence_data.get("metadata", {}).get("compliance_framework", "custom"),
                    "findings_count": len(evidence_data.get("metadata", {}).get("findings", [])),
                    "severity": evidence_data.get("metadata", {}).get("max_severity", "medium")
                }
            }
        
        # Generate trace IDs for distributed tracing
        trace_id = f"trace-{uuid.uuid4()}"
        span_id = f"span-{uuid.uuid4()}"
        
        # Determine priority based on event content
        priority = "normal"
        if "critical" in str(evidence_data).lower():
            priority = "high"
        elif "security" in evidence_event_type:
            priority = "high"
        elif "financial" in evidence_event_type:
            priority = "high"
        
        # Create the pipeline event
        pipeline_event = {
            "event_id": event_id,
            "event_type": {
                pulsar_event_type: event_specific_data.get(pulsar_event_type, {})
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "afdp-test-publisher",
            "actor": evidence_data.get("actor", {
                "actor_type": "test_system",
                "id": "pulsar-test-publisher",
                "auth_provider": "test"
            }),
            "artifacts": evidence_data.get("artifacts", []),
            "metadata": evidence_data.get("metadata", {}),
            "trace_id": trace_id,
            "span_id": span_id,
            "priority": priority,
            "workflow_config": {
                "workflow_type": "simple_signing",
                "auto_approve": False,
                "required_approvers": [],
                "timeout_minutes": 30,
                "retry_policy": {
                    "max_retries": 3,
                    "retry_delay_seconds": 10
                }
            }
        }
        
        return pipeline_event
    
    async def publish_event(self, event_data: Dict, correlation_id: str = None) -> bool:
        """Publish a single event to Pulsar"""
        if correlation_id is None:
            correlation_id = str(uuid.uuid4())
        
        start_time = time.time()
        
        try:
            # Convert to JSON
            event_json = json.dumps(event_data, indent=None, separators=(',', ':'))
            
            # Create message properties for tracing and correlation
            properties = {
                'correlation_id': correlation_id,
                'event_id': event_data.get('event_id', 'unknown'),
                'event_type': json.dumps(event_data.get('event_type', 'unknown')),
                'source': event_data.get('source', 'unknown'),
                'priority': event_data.get('priority', 'normal'),
                'trace_id': event_data.get('trace_id', ''),
                'span_id': event_data.get('span_id', ''),
                'publisher': 'afdp-test-suite',
                'schema_version': '1.0'
            }
            
            # Publish the message
            self.producer.send(
                content=event_json.encode('utf-8'),
                properties=properties,
                partition_key=event_data.get('event_id', correlation_id),
                sequence_id=None,
                replication_clusters=None,
                disable_replication=False
            )
            
            publish_time = (time.time() - start_time) * 1000
            
            self.metrics.total_events += 1
            self.metrics.successful_events += 1
            
            # Update average publish time
            if self.metrics.successful_events == 1:
                self.metrics.avg_publish_time_ms = publish_time
            else:
                self.metrics.avg_publish_time_ms = (
                    (self.metrics.avg_publish_time_ms * (self.metrics.successful_events - 1) + publish_time) /
                    self.metrics.successful_events
                )
            
            self.logger.info(
                f'"action": "event_published", "correlation_id": "{correlation_id}", '
                f'"event_id": "{event_data.get("event_id")}", '
                f'"event_type": "{list(event_data.get("event_type", {}).keys())[0] if event_data.get("event_type") else "unknown"}", '
                f'"publish_time_ms": {publish_time:.2f}'
            )
            
            return True
            
        except Exception as e:
            publish_time = (time.time() - start_time) * 1000
            self.metrics.total_events += 1
            self.metrics.failed_events += 1
            
            self.logger.error(
                f'"action": "event_publish_failed", "correlation_id": "{correlation_id}", '
                f'"error": "{str(e)}", "publish_time_ms": {publish_time:.2f}'
            )
            
            return False
    
    async def publish_batch_events(self, events: List[Dict], batch_delay_ms: int = 100) -> List[bool]:
        """Publish a batch of events with controlled timing"""
        results = []
        
        self.logger.info(
            f'"action": "batch_publish_start", "batch_size": {len(events)}, '
            f'"batch_delay_ms": {batch_delay_ms}'
        )
        
        for i, event in enumerate(events):
            correlation_id = f"batch-{uuid.uuid4()}"
            result = await self.publish_event(event, correlation_id)
            results.append(result)
            
            # Add delay between events if specified
            if batch_delay_ms > 0 and i < len(events) - 1:
                await asyncio.sleep(batch_delay_ms / 1000.0)
        
        successful_count = sum(1 for r in results if r)
        
        self.logger.info(
            f'"action": "batch_publish_complete", "total_events": {len(events)}, '
            f'"successful_events": {successful_count}, "failed_events": {len(events) - successful_count}'
        )
        
        return results
    
    async def publish_continuous_stream(self, events: List[Dict], rate_per_second: float, duration_seconds: int) -> int:
        """Publish events at a controlled rate for a specified duration"""
        if rate_per_second <= 0:
            raise ValueError("Rate must be positive")
        
        interval = 1.0 / rate_per_second
        end_time = time.time() + duration_seconds
        published_count = 0
        
        self.logger.info(
            f'"action": "continuous_stream_start", "rate_per_second": {rate_per_second}, '
            f'"duration_seconds": {duration_seconds}, "interval_seconds": {interval:.3f}'
        )
        
        while time.time() < end_time:
            # Select a random event from the list
            event = random.choice(events)
            
            # Modify the event to make it unique
            unique_event = event.copy()
            unique_event["event_id"] = str(uuid.uuid4())
            unique_event["timestamp"] = datetime.now(timezone.utc).isoformat()
            
            # Add some variability to metadata
            if "metadata" in unique_event:
                unique_event["metadata"] = unique_event["metadata"].copy()
                unique_event["metadata"]["stream_sequence"] = published_count
                unique_event["metadata"]["stream_timestamp"] = time.time()
            
            correlation_id = f"stream-{uuid.uuid4()}"
            success = await self.publish_event(unique_event, correlation_id)
            
            if success:
                published_count += 1
            
            # Wait for next interval
            await asyncio.sleep(interval)
        
        self.logger.info(
            f'"action": "continuous_stream_complete", "published_count": {published_count}, '
            f'"target_count": {int(rate_per_second * duration_seconds)}'
        )
        
        return published_count
    
    async def publish_burst_events(self, events: List[Dict], burst_size: int, burst_interval_seconds: float, num_bursts: int) -> int:
        """Publish events in bursts to test consumer resilience"""
        total_published = 0
        
        self.logger.info(
            f'"action": "burst_test_start", "burst_size": {burst_size}, '
            f'"burst_interval_seconds": {burst_interval_seconds}, "num_bursts": {num_bursts}'
        )
        
        for burst_num in range(num_bursts):
            self.logger.info(f'"action": "burst_start", "burst_number": {burst_num + 1}')
            
            # Select events for this burst
            burst_events = []
            for i in range(burst_size):
                base_event = random.choice(events)
                unique_event = base_event.copy()
                unique_event["event_id"] = str(uuid.uuid4())
                unique_event["timestamp"] = datetime.now(timezone.utc).isoformat()
                unique_event["metadata"] = unique_event.get("metadata", {}).copy()
                unique_event["metadata"]["burst_number"] = burst_num + 1
                unique_event["metadata"]["burst_sequence"] = i + 1
                burst_events.append(unique_event)
            
            # Publish burst as quickly as possible
            results = await self.publish_batch_events(burst_events, batch_delay_ms=0)
            burst_published = sum(1 for r in results if r)
            total_published += burst_published
            
            self.logger.info(
                f'"action": "burst_complete", "burst_number": {burst_num + 1}, '
                f'"published": {burst_published}, "target": {burst_size}'
            )
            
            # Wait between bursts (except for the last one)
            if burst_num < num_bursts - 1:
                await asyncio.sleep(burst_interval_seconds)
        
        self.logger.info(
            f'"action": "burst_test_complete", "total_published": {total_published}, '
            f'"target_total": {burst_size * num_bursts}'
        )
        
        return total_published
    
    def get_metrics(self) -> Dict:
        """Get publishing metrics"""
        duration = (self.metrics.end_time if self.metrics.end_time > 0 else time.time()) - self.metrics.start_time
        
        return {
            "total_events": self.metrics.total_events,
            "successful_events": self.metrics.successful_events,
            "failed_events": self.metrics.failed_events,
            "success_rate": self.metrics.successful_events / self.metrics.total_events if self.metrics.total_events > 0 else 0,
            "avg_publish_time_ms": self.metrics.avg_publish_time_ms,
            "events_per_second": self.metrics.events_per_second if self.metrics.events_per_second > 0 else (self.metrics.total_events / duration if duration > 0 else 0),
            "duration_seconds": duration
        }


async def load_sample_evidence() -> List[Dict]:
    """Load all sample evidence data for event publishing"""
    sample_dir = Path("../sample-data")
    evidence_files = []
    
    for json_file in sample_dir.rglob("*.json"):
        if json_file.name != "test-scenarios.json":
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    evidence_files.append(data)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
    
    return evidence_files


async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="AFDP Notary Service Pulsar Event Publisher")
    parser.add_argument("--service-url", default="pulsar://localhost:6650", help="Pulsar service URL")
    parser.add_argument("--mode", choices=["single", "batch", "stream", "burst"], default="single", help="Publishing mode")
    parser.add_argument("--rate", type=float, default=10.0, help="Events per second for stream mode")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds for stream mode")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size for batch/burst modes")
    parser.add_argument("--burst-interval", type=float, default=5.0, help="Interval between bursts in seconds")
    parser.add_argument("--num-bursts", type=int, default=3, help="Number of bursts for burst mode")
    parser.add_argument("--delay", type=int, default=100, help="Delay between batch events in milliseconds")
    parser.add_argument("--output", default="pulsar-publish-results.json", help="Output file for metrics")
    
    args = parser.parse_args()
    
    print(f"🚀 Starting Pulsar Event Publisher")
    print(f"📡 Service URL: {args.service_url}")
    print(f"🔧 Mode: {args.mode}")
    
    try:
        # Load sample evidence data
        evidence_samples = await load_sample_evidence()
        if not evidence_samples:
            print("❌ No sample evidence data found")
            return
        
        print(f"📁 Loaded {len(evidence_samples)} evidence samples")
        
        async with PulsarEventPublisher(args.service_url) as publisher:
            # Convert evidence to pipeline events
            pipeline_events = []
            for evidence in evidence_samples:
                pipeline_event = publisher.create_pipeline_event(evidence)
                pipeline_events.append(pipeline_event)
            
            print(f"🔄 Converted {len(pipeline_events)} evidence packages to pipeline events")
            
            # Execute based on mode
            if args.mode == "single":
                print("📤 Publishing single events...")
                for i, event in enumerate(pipeline_events, 1):
                    success = await publisher.publish_event(event, f"single-{i}")
                    print(f"{'✅' if success else '❌'} Event {i}/{len(pipeline_events)}")
                    
            elif args.mode == "batch":
                print(f"📦 Publishing batch of {args.batch_size} events...")
                batch_events = pipeline_events[:args.batch_size]
                results = await publisher.publish_batch_events(batch_events, args.delay)
                successful = sum(1 for r in results if r)
                print(f"✅ Published {successful}/{len(batch_events)} events successfully")
                
            elif args.mode == "stream":
                print(f"🌊 Publishing continuous stream ({args.rate} events/sec for {args.duration}s)...")
                published_count = await publisher.publish_continuous_stream(
                    pipeline_events, args.rate, args.duration
                )
                print(f"✅ Published {published_count} events in stream")
                
            elif args.mode == "burst":
                print(f"💥 Publishing {args.num_bursts} bursts of {args.batch_size} events...")
                published_count = await publisher.publish_burst_events(
                    pipeline_events, args.batch_size, args.burst_interval, args.num_bursts
                )
                print(f"✅ Published {published_count} events in bursts")
            
            # Get final metrics
            metrics = publisher.get_metrics()
            
            # Save metrics to file
            with open(args.output, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            # Print summary
            print(f"\n📊 Publishing Summary:")
            print(f"   Total Events: {metrics['total_events']}")
            print(f"   Successful: {metrics['successful_events']}")
            print(f"   Failed: {metrics['failed_events']}")
            print(f"   Success Rate: {metrics['success_rate']:.1%}")
            print(f"   Avg Publish Time: {metrics['avg_publish_time_ms']:.1f}ms")
            print(f"   Events/Second: {metrics['events_per_second']:.1f}")
            print(f"   Duration: {metrics['duration_seconds']:.1f}s")
            print(f"\n💾 Metrics saved to: {args.output}")
            
    except KeyboardInterrupt:
        print("\n⏹️  Publishing interrupted by user")
    except Exception as e:
        print(f"\n💥 Publishing failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())