#!/usr/bin/env python3
"""
Comprehensive gRPC Performance Test Suite for AFDP Notary Service

This script provides high-performance testing of all gRPC endpoints with:
- Load testing with configurable concurrency
- Comprehensive performance metrics
- Protocol Buffer message generation
- Streaming tests and health monitoring
"""

import asyncio
import grpc
import json
import time
import uuid
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, AsyncIterator
import argparse
import logging
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import sys
import traceback

# Import the generated protobuf modules
# Note: These would be generated from the proto file
try:
    # These imports would work after running protoc on the proto file
    import notary_pb2
    import notary_pb2_grpc
except ImportError:
    print("⚠️  protobuf modules not found. Please generate them first:")
    print("   python -m grpc_tools.protoc -I../proto --python_out=. --grpc_python_out=. ../proto/notary.proto")
    sys.exit(1)


@dataclass
class GrpcTestResult:
    """Result of a single gRPC test case"""
    method: str
    scenario_id: str
    scenario_name: str
    success: bool
    response_time_ms: float
    request_size_bytes: int
    response_size_bytes: int
    status_code: Optional[grpc.StatusCode] = None
    error_message: Optional[str] = None
    correlation_id: str = ""


@dataclass
class GrpcTestMetrics:
    """Aggregated gRPC test metrics"""
    total_tests: int
    successful_tests: int
    failed_tests: int
    average_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    total_duration_seconds: float
    requests_per_second: float
    average_request_size_bytes: float
    average_response_size_bytes: float
    error_distribution: Dict[str, int]


class AFDPNotaryGrpcTester:
    """High-performance gRPC test client for AFDP Notary Service"""
    
    def __init__(self, server_address: str = "localhost:50051"):
        self.server_address = server_address
        self.channel: Optional[grpc.aio.Channel] = None
        self.stub: Optional[notary_pb2_grpc.NotaryServiceStub] = None
        self.logger = self._setup_logging()
        self.results: List[GrpcTestResult] = []
        
    def _setup_logging(self) -> logging.Logger:
        """Configure structured JSON logging"""
        logger = logging.getLogger("afdp-grpc-tester")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"component": "grpc-tester", "message": %(message)s}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    async def __aenter__(self):
        """Async context manager entry"""
        # Configure channel with performance optimizations
        channel_options = [
            ('grpc.keepalive_time_ms', 10000),
            ('grpc.keepalive_timeout_ms', 5000),
            ('grpc.keepalive_permit_without_calls', True),
            ('grpc.http2.max_pings_without_data', 0),
            ('grpc.http2.min_time_between_pings_ms', 10000),
            ('grpc.http2.min_ping_interval_without_data_ms', 300000),
            ('grpc.max_send_message_length', 100 * 1024 * 1024),  # 100MB
            ('grpc.max_receive_message_length', 100 * 1024 * 1024),  # 100MB
        ]
        
        self.channel = grpc.aio.insecure_channel(
            self.server_address,
            options=channel_options
        )
        
        self.stub = notary_pb2_grpc.NotaryServiceStub(self.channel)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.channel:
            await self.channel.close()
    
    def _create_evidence_package_from_json(self, json_data: Dict) -> notary_pb2.EvidencePackage:
        """Convert JSON evidence data to protobuf EvidencePackage"""
        # Create timestamp
        timestamp = notary_pb2.google_dot_protobuf_dot_timestamp__pb2.Timestamp()
        if "timestamp" in json_data:
            # Parse ISO timestamp
            dt = datetime.fromisoformat(json_data["timestamp"].replace('Z', '+00:00'))
            timestamp.FromDatetime(dt)
        else:
            timestamp.FromDatetime(datetime.now(timezone.utc))
        
        # Create actor
        actor_data = json_data.get("actor", {})
        actor = notary_pb2.Actor(
            actor_type=actor_data.get("actor_type", "unknown"),
            id=actor_data.get("id", "test-user"),
            auth_provider=actor_data.get("auth_provider", "")
        )
        
        # Create artifacts
        artifacts = []
        for artifact_data in json_data.get("artifacts", []):
            artifact = notary_pb2.Artifact(
                name=artifact_data.get("name", ""),
                uri=artifact_data.get("uri", ""),
                hash_sha256=artifact_data.get("hash_sha256", "")
            )
            artifacts.append(artifact)
        
        # Create metadata
        from google.protobuf import struct_pb2
        metadata = struct_pb2.Struct()
        if "metadata" in json_data and isinstance(json_data["metadata"], dict):
            for key, value in json_data["metadata"].items():
                if isinstance(value, (str, int, float, bool)):
                    metadata[key] = value
                else:
                    metadata[key] = str(value)
        
        # Create evidence package
        evidence_package = notary_pb2.EvidencePackage(
            spec_version="1.0",
            timestamp_utc=timestamp,
            event_type=json_data.get("event_type", "test.event"),
            actor=actor,
            artifacts=artifacts,
            metadata=metadata
        )
        
        return evidence_package
    
    async def health_check(self, correlation_id: str) -> GrpcTestResult:
        """Test the health check endpoint"""
        start_time = time.time()
        
        try:
            request = notary_pb2.HealthRequest()
            request_size = request.ByteSize()
            
            self.logger.info(
                f'"action": "grpc_health_check", "correlation_id": "{correlation_id}"'
            )
            
            response = await self.stub.HealthCheck(
                request,
                metadata=[('correlation-id', correlation_id)]
            )
            
            response_time = (time.time() - start_time) * 1000
            response_size = response.ByteSize()
            
            result = GrpcTestResult(
                method="HealthCheck",
                scenario_id="health-check",
                scenario_name="Health Check",
                success=True,
                response_time_ms=response_time,
                request_size_bytes=request_size,
                response_size_bytes=response_size,
                correlation_id=correlation_id
            )
            
            self.logger.info(
                f'"action": "grpc_health_success", "correlation_id": "{correlation_id}", '
                f'"response_time_ms": {response_time:.2f}, "status": "{response.status}"'
            )
            
            return result
            
        except grpc.RpcError as e:
            response_time = (time.time() - start_time) * 1000
            self.logger.error(
                f'"action": "grpc_health_failed", "correlation_id": "{correlation_id}", '
                f'"status_code": "{e.code()}", "details": "{e.details()}"'
            )
            
            return GrpcTestResult(
                method="HealthCheck",
                scenario_id="health-check",
                scenario_name="Health Check",
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                status_code=e.code(),
                error_message=e.details(),
                correlation_id=correlation_id
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="HealthCheck",
                scenario_id="health-check",
                scenario_name="Health Check",
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def sign_evidence(self, evidence_data: Dict, correlation_id: str) -> GrpcTestResult:
        """Test the SignEvidence endpoint"""
        start_time = time.time()
        scenario_id = evidence_data.get("metadata", {}).get("model_id", "unknown")
        scenario_name = f"{evidence_data.get('event_type', 'unknown')} - {scenario_id}"
        
        try:
            evidence_package = self._create_evidence_package_from_json(evidence_data)
            request = notary_pb2.SignEvidenceRequest(evidence_package=evidence_package)
            request_size = request.ByteSize()
            
            self.logger.info(
                f'"action": "grpc_sign_request", "correlation_id": "{correlation_id}", '
                f'"scenario": "{scenario_name}", "request_size": {request_size}'
            )
            
            response = await self.stub.SignEvidence(
                request,
                metadata=[('correlation-id', correlation_id)]
            )
            
            response_time = (time.time() - start_time) * 1000
            response_size = response.ByteSize()
            
            result = GrpcTestResult(
                method="SignEvidence",
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                success=True,
                response_time_ms=response_time,
                request_size_bytes=request_size,
                response_size_bytes=response_size,
                correlation_id=correlation_id
            )
            
            self.logger.info(
                f'"action": "grpc_sign_success", "correlation_id": "{correlation_id}", '
                f'"response_time_ms": {response_time:.2f}, '
                f'"workflow_id": "{response.workflow_id}", '
                f'"status": "{response.status}"'
            )
            
            return result
            
        except grpc.RpcError as e:
            response_time = (time.time() - start_time) * 1000
            self.logger.error(
                f'"action": "grpc_sign_failed", "correlation_id": "{correlation_id}", '
                f'"status_code": "{e.code()}", "details": "{e.details()}"'
            )
            
            return GrpcTestResult(
                method="SignEvidence",
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                status_code=e.code(),
                error_message=e.details(),
                correlation_id=correlation_id
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="SignEvidence",
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def sign_evidence_with_approval(self, evidence_data: Dict, approvers: List[str], correlation_id: str) -> GrpcTestResult:
        """Test the SignEvidenceWithApproval endpoint"""
        start_time = time.time()
        scenario_id = evidence_data.get("metadata", {}).get("model_id", "unknown")
        scenario_name = f"Approval - {evidence_data.get('event_type', 'unknown')} - {scenario_id}"
        
        try:
            evidence_package = self._create_evidence_package_from_json(evidence_data)
            request = notary_pb2.SignEvidenceWithApprovalRequest(
                evidence_package=evidence_package,
                approvers=approvers
            )
            request_size = request.ByteSize()
            
            self.logger.info(
                f'"action": "grpc_approval_request", "correlation_id": "{correlation_id}", '
                f'"scenario": "{scenario_name}", "approvers": {len(approvers)}'
            )
            
            response = await self.stub.SignEvidenceWithApproval(
                request,
                metadata=[('correlation-id', correlation_id)]
            )
            
            response_time = (time.time() - start_time) * 1000
            response_size = response.ByteSize()
            
            result = GrpcTestResult(
                method="SignEvidenceWithApproval",
                scenario_id=f"{scenario_id}-approval",
                scenario_name=scenario_name,
                success=True,
                response_time_ms=response_time,
                request_size_bytes=request_size,
                response_size_bytes=response_size,
                correlation_id=correlation_id
            )
            
            self.logger.info(
                f'"action": "grpc_approval_success", "correlation_id": "{correlation_id}", '
                f'"response_time_ms": {response_time:.2f}, '
                f'"workflow_id": "{response.workflow_id}"'
            )
            
            return result
            
        except grpc.RpcError as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="SignEvidenceWithApproval",
                scenario_id=f"{scenario_id}-approval",
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                status_code=e.code(),
                error_message=e.details(),
                correlation_id=correlation_id
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="SignEvidenceWithApproval",
                scenario_id=f"{scenario_id}-approval",
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def sign_evidence_batch(self, evidence_list: List[Dict], correlation_id: str) -> GrpcTestResult:
        """Test the SignEvidenceBatch endpoint"""
        start_time = time.time()
        scenario_name = f"Batch Signing - {len(evidence_list)} packages"
        
        try:
            evidence_packages = [
                self._create_evidence_package_from_json(evidence_data)
                for evidence_data in evidence_list
            ]
            
            request = notary_pb2.SignEvidenceBatchRequest(
                evidence_packages=evidence_packages
            )
            request_size = request.ByteSize()
            
            self.logger.info(
                f'"action": "grpc_batch_request", "correlation_id": "{correlation_id}", '
                f'"batch_size": {len(evidence_list)}, "request_size": {request_size}'
            )
            
            response = await self.stub.SignEvidenceBatch(
                request,
                metadata=[('correlation-id', correlation_id)]
            )
            
            response_time = (time.time() - start_time) * 1000
            response_size = response.ByteSize()
            
            result = GrpcTestResult(
                method="SignEvidenceBatch",
                scenario_id="batch-signing",
                scenario_name=scenario_name,
                success=True,
                response_time_ms=response_time,
                request_size_bytes=request_size,
                response_size_bytes=response_size,
                correlation_id=correlation_id
            )
            
            self.logger.info(
                f'"action": "grpc_batch_success", "correlation_id": "{correlation_id}", '
                f'"response_time_ms": {response_time:.2f}, '
                f'"batch_workflow_id": "{response.batch_workflow_id}", '
                f'"results_count": {len(response.results)}'
            )
            
            return result
            
        except grpc.RpcError as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="SignEvidenceBatch",
                scenario_id="batch-signing",
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                status_code=e.code(),
                error_message=e.details(),
                correlation_id=correlation_id
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return GrpcTestResult(
                method="SignEvidenceBatch",
                scenario_id="batch-signing",
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                request_size_bytes=0,
                response_size_bytes=0,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def run_concurrent_load_test(
        self, 
        evidence_data: Dict, 
        concurrent_requests: int, 
        duration_seconds: int
    ) -> List[GrpcTestResult]:
        """Run concurrent load test"""
        self.logger.info(
            f'"action": "load_test_start", "concurrent_requests": {concurrent_requests}, '
            f'"duration_seconds": {duration_seconds}'
        )
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        results = []
        
        async def worker():
            while time.time() < end_time:
                correlation_id = f"load-test-{uuid.uuid4()}"
                result = await self.sign_evidence(evidence_data, correlation_id)
                results.append(result)
                await asyncio.sleep(0.01)  # Small delay between requests
        
        # Create worker tasks
        tasks = [asyncio.create_task(worker()) for _ in range(concurrent_requests)]
        
        # Wait for all tasks to complete or timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration_seconds + 10)
        except asyncio.TimeoutError:
            # Cancel remaining tasks
            for task in tasks:
                task.cancel()
        
        self.logger.info(
            f'"action": "load_test_complete", "total_requests": {len(results)}, '
            f'"successful_requests": {sum(1 for r in results if r.success)}'
        )
        
        return results
    
    def calculate_metrics(self, results: List[GrpcTestResult]) -> GrpcTestMetrics:
        """Calculate comprehensive test metrics"""
        if not results:
            return GrpcTestMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {})
        
        successful = [r for r in results if r.success]
        response_times = [r.response_time_ms for r in results]
        request_sizes = [r.request_size_bytes for r in results if r.request_size_bytes > 0]
        response_sizes = [r.response_size_bytes for r in results if r.response_size_bytes > 0]
        
        # Error distribution
        error_distribution = {}
        for result in results:
            if not result.success:
                error_key = result.status_code.name if result.status_code else "UNKNOWN"
                error_distribution[error_key] = error_distribution.get(error_key, 0) + 1
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        p95_index = int(0.95 * len(sorted_times))
        p99_index = int(0.99 * len(sorted_times))
        
        return GrpcTestMetrics(
            total_tests=len(results),
            successful_tests=len(successful),
            failed_tests=len(results) - len(successful),
            average_response_time_ms=statistics.mean(response_times),
            min_response_time_ms=min(response_times),
            max_response_time_ms=max(response_times),
            p95_response_time_ms=sorted_times[p95_index] if sorted_times else 0,
            p99_response_time_ms=sorted_times[p99_index] if sorted_times else 0,
            total_duration_seconds=0,  # Set by caller
            requests_per_second=0,  # Set by caller
            average_request_size_bytes=statistics.mean(request_sizes) if request_sizes else 0,
            average_response_size_bytes=statistics.mean(response_sizes) if response_sizes else 0,
            error_distribution=error_distribution
        )
    
    def generate_report(self, results: List[GrpcTestResult], total_duration: float) -> Dict:
        """Generate comprehensive test report"""
        metrics = self.calculate_metrics(results)
        metrics.total_duration_seconds = total_duration
        metrics.requests_per_second = metrics.total_tests / total_duration if total_duration > 0 else 0
        
        # Group results by method
        methods = {}
        for result in results:
            method_key = result.method
            if method_key not in methods:
                methods[method_key] = []
            methods[method_key].append(result)
        
        method_summaries = {}
        for method_name, method_results in methods.items():
            method_metrics = self.calculate_metrics(method_results)
            method_summaries[method_name] = {
                "total_requests": method_metrics.total_tests,
                "successful_requests": method_metrics.successful_tests,
                "success_rate": method_metrics.successful_tests / method_metrics.total_tests if method_metrics.total_tests > 0 else 0,
                "avg_response_time_ms": method_metrics.average_response_time_ms,
                "p95_response_time_ms": method_metrics.p95_response_time_ms,
                "p99_response_time_ms": method_metrics.p99_response_time_ms,
                "avg_request_size_bytes": method_metrics.average_request_size_bytes,
                "avg_response_size_bytes": method_metrics.average_response_size_bytes
            }
        
        return {
            "test_summary": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "server_address": self.server_address,
                "total_duration_seconds": total_duration,
                "total_tests": metrics.total_tests,
                "successful_tests": metrics.successful_tests,
                "failed_tests": metrics.failed_tests,
                "success_rate": metrics.successful_tests / metrics.total_tests if metrics.total_tests > 0 else 0
            },
            "performance_metrics": {
                "requests_per_second": metrics.requests_per_second,
                "average_response_time_ms": metrics.average_response_time_ms,
                "min_response_time_ms": metrics.min_response_time_ms,
                "max_response_time_ms": metrics.max_response_time_ms,
                "p95_response_time_ms": metrics.p95_response_time_ms,
                "p99_response_time_ms": metrics.p99_response_time_ms,
                "average_request_size_bytes": metrics.average_request_size_bytes,
                "average_response_size_bytes": metrics.average_response_size_bytes
            },
            "error_analysis": {
                "error_distribution": metrics.error_distribution,
                "error_rate": metrics.failed_tests / metrics.total_tests if metrics.total_tests > 0 else 0
            },
            "method_breakdown": method_summaries,
            "detailed_results": [asdict(r) for r in results]
        }


async def load_sample_data() -> List[Dict]:
    """Load all sample evidence data"""
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
    """Main test execution function"""
    parser = argparse.ArgumentParser(description="AFDP Notary Service gRPC Performance Test Suite")
    parser.add_argument("--server", default="localhost:50051", help="gRPC server address")
    parser.add_argument("--load-test", action="store_true", help="Run load tests")
    parser.add_argument("--concurrent", type=int, default=10, help="Concurrent requests for load test")
    parser.add_argument("--duration", type=int, default=30, help="Load test duration in seconds")
    parser.add_argument("--batch-size", type=int, default=5, help="Batch size for batch tests")
    parser.add_argument("--output", default="grpc-performance-results.json", help="Output file for results")
    
    args = parser.parse_args()
    
    print(f"🚀 Starting AFDP Notary Service gRPC Performance Tests")
    print(f"🌐 Target Server: {args.server}")
    
    start_time = time.time()
    
    async with AFDPNotaryGrpcTester(args.server) as tester:
        # Health check first
        health_result = await tester.health_check(f"health-{uuid.uuid4()}")
        if not health_result.success:
            print("❌ Health check failed. Make sure the gRPC server is running.")
            return
        
        print("✅ Health check passed")
        
        # Load sample data
        evidence_samples = await load_sample_data()
        print(f"📁 Loaded {len(evidence_samples)} evidence samples")
        
        all_results = [health_result]
        
        # Test each evidence sample with simple signing
        for i, evidence in enumerate(evidence_samples, 1):
            correlation_id = f"test-{uuid.uuid4()}"
            print(f"🧪 Testing scenario {i}/{len(evidence_samples)}: {evidence.get('event_type', 'unknown')}")
            
            result = await tester.sign_evidence(evidence, correlation_id)
            all_results.append(result)
            
            if result.success:
                print(f"✅ Scenario {i} passed ({result.response_time_ms:.1f}ms, {result.request_size_bytes}B → {result.response_size_bytes}B)")
            else:
                print(f"❌ Scenario {i} failed: {result.error_message}")
        
        # Test approval workflow with first sample
        if evidence_samples:
            print("📋 Testing approval workflow...")
            approval_result = await tester.sign_evidence_with_approval(
                evidence_samples[0],
                ["approver1@company.com", "approver2@company.com"],
                f"approval-{uuid.uuid4()}"
            )
            all_results.append(approval_result)
            
            if approval_result.success:
                print(f"✅ Approval workflow passed ({approval_result.response_time_ms:.1f}ms)")
            else:
                print(f"❌ Approval workflow failed: {approval_result.error_message}")
        
        # Test batch signing
        if len(evidence_samples) >= args.batch_size:
            print(f"📦 Testing batch signing ({args.batch_size} packages)...")
            batch_result = await tester.sign_evidence_batch(
                evidence_samples[:args.batch_size],
                f"batch-{uuid.uuid4()}"
            )
            all_results.append(batch_result)
            
            if batch_result.success:
                print(f"✅ Batch signing passed ({batch_result.response_time_ms:.1f}ms)")
            else:
                print(f"❌ Batch signing failed: {batch_result.error_message}")
        
        # Run load tests if requested
        if args.load_test and evidence_samples:
            print(f"🔥 Running load test ({args.concurrent} concurrent, {args.duration}s duration)")
            load_results = await tester.run_concurrent_load_test(
                evidence_samples[0],
                args.concurrent,
                args.duration
            )
            all_results.extend(load_results)
        
        # Generate report
        total_duration = time.time() - start_time
        report = tester.generate_report(all_results, total_duration)
        
        # Save results
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        summary = report["test_summary"]
        perf = report["performance_metrics"]
        
        print(f"\n📊 Test Summary:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Successful: {summary['successful_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Success Rate: {summary['success_rate']:.1%}")
        print(f"   Duration: {summary['total_duration_seconds']:.1f}s")
        print(f"   Requests/sec: {perf['requests_per_second']:.1f}")
        print(f"   Avg Response Time: {perf['average_response_time_ms']:.1f}ms")
        print(f"   P95 Response Time: {perf['p95_response_time_ms']:.1f}ms")
        print(f"   P99 Response Time: {perf['p99_response_time_ms']:.1f}ms")
        print(f"   Avg Request Size: {perf['average_request_size_bytes']:.0f} bytes")
        print(f"   Avg Response Size: {perf['average_response_size_bytes']:.0f} bytes")
        print(f"\n💾 Detailed results saved to: {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        traceback.print_exc()