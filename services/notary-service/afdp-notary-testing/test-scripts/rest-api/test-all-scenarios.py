#!/usr/bin/env python3
"""
Comprehensive REST API Test Suite for AFDP Notary Service

This script tests all sample evidence packages against the REST API endpoints,
providing detailed logging, performance metrics, and comprehensive reporting.
"""

import asyncio
import aiohttp
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse
import logging
from dataclasses import dataclass
import statistics


@dataclass
class TestResult:
    """Result of a single test case"""
    scenario_id: str
    scenario_name: str
    success: bool
    response_time_ms: float
    status_code: int
    error_message: Optional[str] = None
    response_data: Optional[Dict] = None
    correlation_id: str = ""


@dataclass
class TestMetrics:
    """Aggregated test metrics"""
    total_tests: int
    successful_tests: int
    failed_tests: int
    average_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p95_response_time_ms: float
    total_duration_seconds: float


class AFDPNotaryTester:
    """REST API test client for AFDP Notary Service"""
    
    def __init__(self, base_url: str = "http://localhost:3030"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = self._setup_logging()
        self.results: List[TestResult] = []
        
    def _setup_logging(self) -> logging.Logger:
        """Configure structured JSON logging"""
        logger = logging.getLogger("afdp-notary-tester")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"component": "rest-api-tester", "message": %(message)s}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=30,
            connect=5,
            sock_read=15
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "AFDP-Notary-Tester/1.0",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def health_check(self) -> bool:
        """Check if the notary service is healthy"""
        try:
            async with self.session.get(f"{self.base_url}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    self.logger.info(f'"health_check": "passed", "response": {json.dumps(data)}')
                    return True
                else:
                    self.logger.error(f'"health_check": "failed", "status": {response.status}')
                    return False
        except Exception as e:
            self.logger.error(f'"health_check": "error", "message": "{str(e)}"')
            return False
    
    async def notarize_evidence(self, evidence_data: Dict, correlation_id: str) -> TestResult:
        """Submit evidence for notarization"""
        start_time = time.time()
        scenario_id = evidence_data.get("metadata", {}).get("model_id", "unknown")
        scenario_name = f"{evidence_data.get('event_type', 'unknown')} - {scenario_id}"
        
        try:
            headers = {
                "X-Correlation-ID": correlation_id,
                "X-Request-ID": str(uuid.uuid4()),
                "X-Client-Version": "test-suite-1.0"
            }
            
            self.logger.info(
                f'"action": "notarize_request", "correlation_id": "{correlation_id}", '
                f'"scenario": "{scenario_name}", "event_type": "{evidence_data.get("event_type")}"'
            )
            
            async with self.session.post(
                f"{self.base_url}/api/v1/notarize",
                json=evidence_data,
                headers=headers
            ) as response:
                
                response_time = (time.time() - start_time) * 1000
                response_data = await response.json() if response.content_type == 'application/json' else None
                
                result = TestResult(
                    scenario_id=scenario_id,
                    scenario_name=scenario_name,
                    success=response.status == 200,
                    response_time_ms=response_time,
                    status_code=response.status,
                    response_data=response_data,
                    correlation_id=correlation_id
                )
                
                if response.status == 200:
                    self.logger.info(
                        f'"action": "notarize_success", "correlation_id": "{correlation_id}", '
                        f'"response_time_ms": {response_time:.2f}, '
                        f'"rekor_log_id": "{response_data.get("rekor_log_id", "unknown") if response_data else "unknown"}"'
                    )
                else:
                    error_msg = response_data.get("error", "Unknown error") if response_data else f"HTTP {response.status}"
                    result.error_message = error_msg
                    self.logger.error(
                        f'"action": "notarize_failed", "correlation_id": "{correlation_id}", '
                        f'"status": {response.status}, "error": "{error_msg}"'
                    )
                
                return result
                
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            self.logger.error(
                f'"action": "notarize_timeout", "correlation_id": "{correlation_id}", '
                f'"response_time_ms": {response_time:.2f}'
            )
            return TestResult(
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                status_code=408,
                error_message="Request timeout",
                correlation_id=correlation_id
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.logger.error(
                f'"action": "notarize_error", "correlation_id": "{correlation_id}", '
                f'"error": "{str(e)}"'
            )
            return TestResult(
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                success=False,
                response_time_ms=response_time,
                status_code=500,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def verify_evidence(self, evidence_hash: str, correlation_id: str) -> TestResult:
        """Verify evidence package using its hash"""
        start_time = time.time()
        
        try:
            headers = {
                "X-Correlation-ID": correlation_id,
                "X-Request-ID": str(uuid.uuid4())
            }
            
            self.logger.info(
                f'"action": "verify_request", "correlation_id": "{correlation_id}", '
                f'"evidence_hash": "{evidence_hash}"'
            )
            
            async with self.session.get(
                f"{self.base_url}/api/v1/verify/{evidence_hash}",
                headers=headers
            ) as response:
                
                response_time = (time.time() - start_time) * 1000
                response_data = await response.json() if response.content_type == 'application/json' else None
                
                result = TestResult(
                    scenario_id=evidence_hash[:16],
                    scenario_name=f"Verification - {evidence_hash[:16]}",
                    success=response.status == 200,
                    response_time_ms=response_time,
                    status_code=response.status,
                    response_data=response_data,
                    correlation_id=correlation_id
                )
                
                if response.status == 200:
                    self.logger.info(
                        f'"action": "verify_success", "correlation_id": "{correlation_id}", '
                        f'"response_time_ms": {response_time:.2f}, '
                        f'"verified": {response_data.get("verified", False) if response_data else False}'
                    )
                else:
                    error_msg = response_data.get("error", "Unknown error") if response_data else f"HTTP {response.status}"
                    result.error_message = error_msg
                    self.logger.error(
                        f'"action": "verify_failed", "correlation_id": "{correlation_id}", '
                        f'"status": {response.status}, "error": "{error_msg}"'
                    )
                
                return result
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return TestResult(
                scenario_id=evidence_hash[:16],
                scenario_name=f"Verification - {evidence_hash[:16]}",
                success=False,
                response_time_ms=response_time,
                status_code=500,
                error_message=str(e),
                correlation_id=correlation_id
            )
    
    async def run_load_test(self, evidence_data: Dict, concurrent_requests: int, duration_seconds: int) -> List[TestResult]:
        """Run load test with concurrent requests"""
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
                result = await self.notarize_evidence(evidence_data, correlation_id)
                results.append(result)
                await asyncio.sleep(0.1)  # Small delay between requests
        
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
    
    def calculate_metrics(self, results: List[TestResult]) -> TestMetrics:
        """Calculate test metrics from results"""
        if not results:
            return TestMetrics(0, 0, 0, 0, 0, 0, 0, 0)
        
        successful = [r for r in results if r.success]
        response_times = [r.response_time_ms for r in results]
        
        return TestMetrics(
            total_tests=len(results),
            successful_tests=len(successful),
            failed_tests=len(results) - len(successful),
            average_response_time_ms=statistics.mean(response_times),
            min_response_time_ms=min(response_times),
            max_response_time_ms=max(response_times),
            p95_response_time_ms=statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times),
            total_duration_seconds=0  # Set by caller
        )
    
    def generate_report(self, results: List[TestResult], total_duration: float) -> Dict:
        """Generate comprehensive test report"""
        metrics = self.calculate_metrics(results)
        metrics.total_duration_seconds = total_duration
        
        # Group results by scenario
        scenarios = {}
        for result in results:
            scenario_key = result.scenario_id
            if scenario_key not in scenarios:
                scenarios[scenario_key] = []
            scenarios[scenario_key].append(result)
        
        scenario_summaries = {}
        for scenario_id, scenario_results in scenarios.items():
            scenario_metrics = self.calculate_metrics(scenario_results)
            scenario_summaries[scenario_id] = {
                "name": scenario_results[0].scenario_name,
                "total_requests": scenario_metrics.total_tests,
                "successful_requests": scenario_metrics.successful_tests,
                "success_rate": scenario_metrics.successful_tests / scenario_metrics.total_tests if scenario_metrics.total_tests > 0 else 0,
                "avg_response_time_ms": scenario_metrics.average_response_time_ms,
                "p95_response_time_ms": scenario_metrics.p95_response_time_ms
            }
        
        return {
            "test_summary": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_duration_seconds": total_duration,
                "total_tests": metrics.total_tests,
                "successful_tests": metrics.successful_tests,
                "failed_tests": metrics.failed_tests,
                "success_rate": metrics.successful_tests / metrics.total_tests if metrics.total_tests > 0 else 0
            },
            "performance_metrics": {
                "average_response_time_ms": metrics.average_response_time_ms,
                "min_response_time_ms": metrics.min_response_time_ms,
                "max_response_time_ms": metrics.max_response_time_ms,
                "p95_response_time_ms": metrics.p95_response_time_ms,
                "throughput_requests_per_second": metrics.total_tests / total_duration if total_duration > 0 else 0
            },
            "scenarios": scenario_summaries,
            "detailed_results": [
                {
                    "scenario_id": r.scenario_id,
                    "scenario_name": r.scenario_name,
                    "success": r.success,
                    "response_time_ms": r.response_time_ms,
                    "status_code": r.status_code,
                    "error_message": r.error_message,
                    "correlation_id": r.correlation_id
                }
                for r in results
            ]
        }


async def load_sample_data() -> List[Dict]:
    """Load all sample evidence data"""
    sample_dir = Path("../sample-data")
    evidence_files = []
    
    # Recursively find all JSON files in sample data directory
    for json_file in sample_dir.rglob("*.json"):
        if json_file.name != "test-scenarios.json":  # Skip config file
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    evidence_files.append(data)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
    
    return evidence_files


async def main():
    """Main test execution function"""
    parser = argparse.ArgumentParser(description="AFDP Notary Service REST API Test Suite")
    parser.add_argument("--base-url", default="http://localhost:3030", help="Base URL of the notary service")
    parser.add_argument("--load-test", action="store_true", help="Run load tests")
    parser.add_argument("--concurrent", type=int, default=5, help="Concurrent requests for load test")
    parser.add_argument("--duration", type=int, default=30, help="Load test duration in seconds")
    parser.add_argument("--output", default="rest-api-test-results.json", help="Output file for results")
    
    args = parser.parse_args()
    
    print(f"🚀 Starting AFDP Notary Service REST API Tests")
    print(f"📡 Target URL: {args.base_url}")
    
    start_time = time.time()
    
    async with AFDPNotaryTester(args.base_url) as tester:
        # Health check first
        if not await tester.health_check():
            print("❌ Health check failed. Make sure the notary service is running.")
            return
        
        print("✅ Health check passed")
        
        # Load sample data
        evidence_samples = await load_sample_data()
        print(f"📁 Loaded {len(evidence_samples)} evidence samples")
        
        all_results = []
        
        # Test each evidence sample
        for i, evidence in enumerate(evidence_samples, 1):
            correlation_id = f"test-{uuid.uuid4()}"
            print(f"🧪 Testing scenario {i}/{len(evidence_samples)}: {evidence.get('event_type', 'unknown')}")
            
            result = await tester.notarize_evidence(evidence, correlation_id)
            all_results.append(result)
            
            if result.success:
                print(f"✅ Scenario {i} passed ({result.response_time_ms:.1f}ms)")
                
                # If notarization succeeded, test verification
                if result.response_data and "evidence_package_hash" in result.response_data:
                    verify_result = await tester.verify_evidence(
                        result.response_data["evidence_package_hash"],
                        f"verify-{correlation_id}"
                    )
                    all_results.append(verify_result)
                    
                    if verify_result.success:
                        print(f"✅ Verification passed ({verify_result.response_time_ms:.1f}ms)")
                    else:
                        print(f"❌ Verification failed: {verify_result.error_message}")
            else:
                print(f"❌ Scenario {i} failed: {result.error_message}")
        
        # Run load tests if requested
        if args.load_test and evidence_samples:
            print(f"🔥 Running load test ({args.concurrent} concurrent, {args.duration}s duration)")
            load_results = await tester.run_load_test(
                evidence_samples[0],  # Use first sample for load test
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
        print(f"   Avg Response Time: {perf['average_response_time_ms']:.1f}ms")
        print(f"   P95 Response Time: {perf['p95_response_time_ms']:.1f}ms")
        print(f"   Throughput: {perf['throughput_requests_per_second']:.1f} req/s")
        print(f"\n💾 Detailed results saved to: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())