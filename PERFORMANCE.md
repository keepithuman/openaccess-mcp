# OpenAccess MCP Performance Optimization Guide

This guide covers performance optimization techniques for the OpenAccess MCP server, including connection pooling, caching strategies, and monitoring.

## Table of Contents

1. [Performance Overview](#performance-overview)
2. [Connection Pooling](#connection-pooling)
3. [Caching Strategies](#caching-strategies)
4. [Resource Management](#resource-management)
5. [Monitoring and Metrics](#monitoring-and-metrics)
6. [Benchmarking](#benchmarking)
7. [Production Tuning](#production-tuning)
8. [Troubleshooting Performance Issues](#troubleshooting-performance-issues)

## Performance Overview

### Key Performance Metrics

- **Throughput**: Operations per second
- **Latency**: Response time for operations
- **Concurrency**: Number of simultaneous connections
- **Resource Usage**: CPU, memory, and network utilization
- **Error Rate**: Percentage of failed operations

### Performance Targets

| Metric | Target | Acceptable | Poor |
|--------|--------|------------|------|
| SSH Command Execution | < 100ms | 100-500ms | > 500ms |
| SFTP Transfer (1MB) | < 1s | 1-5s | > 5s |
| Rsync Sync (100 files) | < 10s | 10-30s | > 30s |
| Tunnel Creation | < 200ms | 200-1000ms | > 1000ms |
| VPN Toggle | < 500ms | 500-2000ms | > 2000ms |

## Connection Pooling

### SSH Connection Pooling

Implement connection pooling to reuse SSH connections and reduce connection overhead.

```python
import asyncio
from asyncssh import connect
from typing import Dict, Optional
import time

class SSHConnectionPool:
    def __init__(self, max_connections: int = 10, max_idle_time: int = 300):
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.connections: Dict[str, Dict] = {}
        self.lock = asyncio.Lock()
    
    async def get_connection(self, profile_id: str, host: str, port: int, 
                           username: str, private_key: str) -> Optional[object]:
        """Get a connection from the pool or create a new one."""
        async with self.lock:
            # Check for existing connection
            if profile_id in self.connections:
                conn_info = self.connections[profile_id]
                if time.time() - conn_info['last_used'] < self.max_idle_time:
                    conn_info['last_used'] = time.time()
                    return conn_info['connection']
                else:
                    # Close expired connection
                    await self._close_connection(profile_id)
            
            # Create new connection if pool not full
            if len(self.connections) < self.max_connections:
                try:
                    connection = await connect(
                        host=host,
                        port=port,
                        username=username,
                        client_keys=[private_key],
                        known_hosts=None
                    )
                    
                    self.connections[profile_id] = {
                        'connection': connection,
                        'last_used': time.time(),
                        'created': time.time()
                    }
                    
                    return connection
                except Exception as e:
                    print(f"Failed to create SSH connection: {e}")
                    return None
            
            return None
    
    async def return_connection(self, profile_id: str):
        """Return a connection to the pool."""
        async with self.lock:
            if profile_id in self.connections:
                self.connections[profile_id]['last_used'] = time.time()
    
    async def _close_connection(self, profile_id: str):
        """Close and remove a connection from the pool."""
        if profile_id in self.connections:
            try:
                await self.connections[profile_id]['connection'].close()
            except:
                pass
            del self.connections[profile_id]
    
    async def cleanup_expired(self):
        """Clean up expired connections."""
        async with self.lock:
            current_time = time.time()
            expired = [
                profile_id for profile_id, conn_info in self.connections.items()
                if current_time - conn_info['last_used'] > self.max_idle_time
            ]
            
            for profile_id in expired:
                await self._close_connection(profile_id)
    
    async def close_all(self):
        """Close all connections in the pool."""
        async with self.lock:
            for profile_id in list(self.connections.keys()):
                await self._close_connection(profile_id)
```

### SFTP Connection Pooling

Extend the SSH connection pool to handle SFTP sessions efficiently.

```python
class SFTPConnectionPool(SSHConnectionPool):
    def __init__(self, max_connections: int = 10, max_idle_time: int = 300):
        super().__init__(max_connections, max_idle_time)
        self.sftp_sessions: Dict[str, object] = {}
    
    async def get_sftp_session(self, profile_id: str, **kwargs) -> Optional[object]:
        """Get an SFTP session from the pool."""
        connection = await self.get_connection(profile_id, **kwargs)
        if not connection:
            return None
        
        # Check if SFTP session exists
        if profile_id in self.sftp_sessions:
            return self.sftp_sessions[profile_id]
        
        # Create new SFTP session
        try:
            sftp_session = await connection.start_sftp_client()
            self.sftp_sessions[profile_id] = sftp_session
            return sftp_session
        except Exception as e:
            print(f"Failed to create SFTP session: {e}")
            return None
```

## Caching Strategies

### Response Caching

Implement response caching for frequently requested operations.

```python
import json
import hashlib
from typing import Any, Optional
import time

class ResponseCache:
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: Dict[str, Dict] = {}
        self.access_order: List[str] = []
    
    def _generate_key(self, operation: str, params: Dict[str, Any]) -> str:
        """Generate a cache key for an operation."""
        param_str = json.dumps(params, sort_keys=True)
        return f"{operation}:{hashlib.sha256(param_str.encode()).hexdigest()}"
    
    def get(self, operation: str, params: Dict[str, Any]) -> Optional[Any]:
        """Get a cached response."""
        key = self._generate_key(operation, params)
        
        if key in self.cache:
            cache_entry = self.cache[key]
            
            # Check if entry is expired
            if time.time() - cache_entry['timestamp'] > self.ttl:
                self._remove(key)
                return None
            
            # Update access order
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            
            return cache_entry['data']
        
        return None
    
    def set(self, operation: str, params: Dict[str, Any], data: Any):
        """Cache a response."""
        key = self._generate_key(operation, params)
        
        # Remove oldest entry if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = self.access_order.pop(0)
            self._remove(oldest_key)
        
        # Add new entry
        self.cache[key] = {
            'data': data,
            'timestamp': time.time()
        }
        self.access_order.append(key)
    
    def _remove(self, key: str):
        """Remove an entry from the cache."""
        if key in self.cache:
            del self.cache[key]
        if key in self.access_order:
            self.access_order.remove(key)
    
    def clear(self):
        """Clear all cached entries."""
        self.cache.clear()
        self.access_order.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hit_rate': self._calculate_hit_rate(),
            'ttl': self.ttl
        }
    
    def _calculate_hit_rate(self) -> float:
        """Calculate cache hit rate (placeholder implementation)."""
        # This would need to track hits and misses
        return 0.0
```

### Profile Caching

Cache profile configurations to avoid repeated file reads.

```python
class ProfileCache:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self.cache: Dict[str, Dict] = {}
        self.timestamps: Dict[str, float] = {}
    
    def get_profile(self, profile_id: str) -> Optional[Dict]:
        """Get a cached profile."""
        if profile_id in self.cache:
            if time.time() - self.timestamps[profile_id] < self.ttl:
                return self.cache[profile_id]
            else:
                # Remove expired entry
                self._remove(profile_id)
        
        return None
    
    def set_profile(self, profile_id: str, profile: Dict):
        """Cache a profile."""
        self.cache[profile_id] = profile
        self.timestamps[profile_id] = time.time()
    
    def _remove(self, profile_id: str):
        """Remove a profile from cache."""
        if profile_id in self.cache:
            del self.cache[profile_id]
        if profile_id in self.timestamps:
            del self.timestamps[profile_id]
    
    def invalidate(self, profile_id: str):
        """Invalidate a cached profile."""
        self._remove(profile_id)
    
    def clear(self):
        """Clear all cached profiles."""
        self.cache.clear()
        self.timestamps.clear()
```

## Resource Management

### Memory Management

Implement proper memory management to prevent memory leaks.

```python
import gc
import psutil
import asyncio
from typing import Dict, Any

class ResourceManager:
    def __init__(self, max_memory_mb: int = 1024, cleanup_interval: int = 300):
        self.max_memory_mb = max_memory_mb
        self.cleanup_interval = cleanup_interval
        self.monitoring_task: Optional[asyncio.Task] = None
    
    async def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring_task = asyncio.create_task(self._monitor_resources())
    
    async def stop_monitoring(self):
        """Stop resource monitoring."""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
    
    async def _monitor_resources(self):
        """Monitor system resources."""
        while True:
            try:
                await self._check_memory_usage()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Resource monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_memory_usage(self):
        """Check memory usage and trigger cleanup if needed."""
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        if memory_mb > self.max_memory_mb:
            print(f"Memory usage high: {memory_mb:.2f}MB, triggering cleanup")
            await self._cleanup_resources()
    
    async def _cleanup_resources(self):
        """Clean up resources to free memory."""
        # Force garbage collection
        gc.collect()
        
        # Clear caches
        # This would call clear() on various cache objects
        
        # Log cleanup
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        print(f"Cleanup completed. Memory usage: {memory_mb:.2f}MB")
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get current resource statistics."""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'memory_rss_mb': memory_info.rss / 1024 / 1024,
            'memory_vms_mb': memory_info.vms / 1024 / 1024,
            'cpu_percent': process.cpu_percent(),
            'num_threads': process.num_threads(),
            'open_files': len(process.open_files()),
            'connections': len(process.connections())
        }
```

### Connection Limits

Implement connection limits to prevent resource exhaustion.

```python
class ConnectionLimiter:
    def __init__(self, max_connections: int = 100, max_per_profile: int = 10):
        self.max_connections = max_connections
        self.max_per_profile = max_per_profile
        self.active_connections: Dict[str, int] = {}
        self.total_connections = 0
        self.lock = asyncio.Lock()
    
    async def acquire_connection(self, profile_id: str) -> bool:
        """Acquire a connection slot."""
        async with self.lock:
            # Check total connection limit
            if self.total_connections >= self.max_connections:
                return False
            
            # Check per-profile connection limit
            profile_connections = self.active_connections.get(profile_id, 0)
            if profile_connections >= self.max_per_profile:
                return False
            
            # Acquire connection
            self.active_connections[profile_id] = profile_connections + 1
            self.total_connections += 1
            return True
    
    async def release_connection(self, profile_id: str):
        """Release a connection slot."""
        async with self.lock:
            if profile_id in self.active_connections:
                self.active_connections[profile_id] -= 1
                if self.active_connections[profile_id] <= 0:
                    del self.active_connections[profile_id]
                self.total_connections -= 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'total_connections': self.total_connections,
            'max_connections': self.max_connections,
            'active_connections': dict(self.active_connections),
            'max_per_profile': self.max_per_profile
        }
```

## Monitoring and Metrics

### Performance Metrics Collection

Implement comprehensive metrics collection for performance monitoring.

```python
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
import statistics

@dataclass
class OperationMetrics:
    operation: str
    count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    error_count: int = 0
    
    @property
    def avg_time(self) -> float:
        return self.total_time / self.count if self.count > 0 else 0.0
    
    @property
    def error_rate(self) -> float:
        return self.error_count / self.count if self.count > 0 else 0.0

class PerformanceMonitor:
    def __init__(self):
        self.metrics: Dict[str, OperationMetrics] = {}
        self.lock = asyncio.Lock()
    
    async def record_operation(self, operation: str, duration: float, 
                             success: bool = True):
        """Record operation performance metrics."""
        async with self.lock:
            if operation not in self.metrics:
                self.metrics[operation] = OperationMetrics(operation=operation)
            
            metrics = self.metrics[operation]
            metrics.count += 1
            metrics.total_time += duration
            metrics.min_time = min(metrics.min_time, duration)
            metrics.max_time = max(metrics.max_time, duration)
            
            if not success:
                metrics.error_count += 1
    
    async def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all performance metrics."""
        async with self.lock:
            return {
                operation: {
                    'count': metrics.count,
                    'avg_time': metrics.avg_time,
                    'min_time': metrics.min_time if metrics.min_time != float('inf') else 0.0,
                    'max_time': metrics.max_time,
                    'error_count': metrics.error_count,
                    'error_rate': metrics.error_rate
                }
                for operation, metrics in self.metrics.items()
            }
    
    async def reset_metrics(self):
        """Reset all metrics."""
        async with self.lock:
            self.metrics.clear()
```

### Health Checks

Implement comprehensive health checks for monitoring.

```python
class HealthChecker:
    def __init__(self, server):
        self.server = server
        self.last_check = time.time()
        self.check_interval = 30
    
    async def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        current_time = time.time()
        
        # Only check if enough time has passed
        if current_time - self.last_check < self.check_interval:
            return self._get_cached_health()
        
        health_status = await self._perform_health_check()
        self.last_check = current_time
        
        return health_status
    
    async def _perform_health_check(self) -> Dict[str, Any]:
        """Perform actual health checks."""
        checks = {
            'server_status': await self._check_server_status(),
            'database_connectivity': await self._check_database(),
            'ssh_connectivity': await self._check_ssh_connectivity(),
            'resource_usage': self._check_resource_usage(),
            'cache_health': self._check_cache_health(),
            'connection_pool_health': self._check_connection_pools()
        }
        
        overall_healthy = all(check['healthy'] for check in checks.values())
        
        return {
            'healthy': overall_healthy,
            'timestamp': time.time(),
            'checks': checks
        }
    
    async def _check_server_status(self) -> Dict[str, Any]:
        """Check if the server is responding."""
        try:
            # Simple ping test
            return {'healthy': True, 'message': 'Server responding'}
        except Exception as e:
            return {'healthy': False, 'message': str(e)}
    
    async def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            # Test database connection
            return {'healthy': True, 'message': 'Database accessible'}
        except Exception as e:
            return {'healthy': False, 'message': str(e)}
    
    def _check_resource_usage(self) -> Dict[str, Any]:
        """Check system resource usage."""
        try:
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
            
            healthy = memory_mb < 1024 and cpu_percent < 80
            
            return {
                'healthy': healthy,
                'memory_mb': memory_mb,
                'cpu_percent': cpu_percent,
                'message': f'Memory: {memory_mb:.1f}MB, CPU: {cpu_percent:.1f}%'
            }
        except Exception as e:
            return {'healthy': False, 'message': str(e)}
    
    def _get_cached_health(self) -> Dict[str, Any]:
        """Get cached health status."""
        # This would return the last known health status
        return {'healthy': True, 'message': 'Cached health status'}
```

## Benchmarking

### Performance Testing

Create comprehensive performance tests to measure system performance.

```python
import asyncio
import time
from typing import List, Dict, Any

class PerformanceBenchmark:
    def __init__(self, server):
        self.server = server
        self.results: List[Dict[str, Any]] = []
    
    async def run_ssh_benchmark(self, profile_id: str, iterations: int = 100) -> Dict[str, Any]:
        """Benchmark SSH command execution."""
        print(f"Running SSH benchmark with {iterations} iterations...")
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start_time = time.time()
            
            try:
                result = await self.server.ssh_exec(
                    profile_id=profile_id,
                    command="echo 'benchmark test'",
                    caller="benchmark"
                )
                
                if result["success"]:
                    duration = time.time() - start_time
                    times.append(duration)
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
                print(f"Error in iteration {i}: {e}")
        
        if times:
            stats = {
                'operation': 'ssh.exec',
                'iterations': iterations,
                'successful': len(times),
                'errors': errors,
                'avg_time': statistics.mean(times),
                'min_time': min(times),
                'max_time': max(times),
                'p95_time': statistics.quantiles(times, n=20)[18] if len(times) >= 20 else None,
                'p99_time': statistics.quantiles(times, n=100)[98] if len(times) >= 100 else None
            }
        else:
            stats = {
                'operation': 'ssh.exec',
                'iterations': iterations,
                'successful': 0,
                'errors': errors,
                'avg_time': 0,
                'min_time': 0,
                'max_time': 0,
                'p95_time': None,
                'p99_time': None
            }
        
        self.results.append(stats)
        return stats
    
    async def run_sftp_benchmark(self, profile_id: str, file_size_mb: int = 1, 
                                iterations: int = 50) -> Dict[str, Any]:
        """Benchmark SFTP file transfer."""
        print(f"Running SFTP benchmark with {iterations} iterations, {file_size_mb}MB files...")
        
        # Create test file
        test_file = f"/tmp/benchmark_{file_size_mb}mb.dat"
        with open(test_file, 'wb') as f:
            f.write(b'0' * (file_size_mb * 1024 * 1024))
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start_time = time.time()
            
            try:
                result = await self.server.sftp_transfer(
                    profile_id=profile_id,
                    direction="upload",
                    local_path=test_file,
                    remote_path=f"/tmp/benchmark_{i}.dat",
                    caller="benchmark"
                )
                
                if result["success"]:
                    duration = time.time() - start_time
                    times.append(duration)
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
                print(f"Error in iteration {i}: {e}")
        
        # Cleanup test file
        import os
        os.remove(test_file)
        
        if times:
            stats = {
                'operation': 'sftp.transfer',
                'iterations': iterations,
                'file_size_mb': file_size_mb,
                'successful': len(times),
                'errors': errors,
                'avg_time': statistics.mean(times),
                'min_time': min(times),
                'max_time': max(times),
                'throughput_mbps': (file_size_mb * 8) / statistics.mean(times)
            }
        else:
            stats = {
                'operation': 'sftp.transfer',
                'iterations': iterations,
                'file_size_mb': file_size_mb,
                'successful': 0,
                'errors': errors,
                'avg_time': 0,
                'min_time': 0,
                'max_time': 0,
                'throughput_mbps': 0
            }
        
        self.results.append(stats)
        return stats
    
    def print_results(self):
        """Print benchmark results."""
        print("\n" + "="*60)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("="*60)
        
        for result in self.results:
            print(f"\n{result['operation'].upper()}")
            print(f"  Iterations: {result['iterations']}")
            print(f"  Successful: {result['successful']}")
            print(f"  Errors: {result['errors']}")
            print(f"  Average Time: {result['avg_time']:.3f}s")
            print(f"  Min Time: {result['min_time']:.3f}s")
            print(f"  Max Time: {result['max_time']:.3f}s")
            
            if 'p95_time' in result and result['p95_time']:
                print(f"  95th Percentile: {result['p95_time']:.3f}s")
            
            if 'throughput_mbps' in result:
                print(f"  Throughput: {result['throughput_mbps']:.2f} Mbps")
        
        print("\n" + "="*60)
```

## Production Tuning

### Configuration Optimization

Optimize configuration for production environments.

```python
# Production configuration example
PRODUCTION_CONFIG = {
    'connection_pooling': {
        'max_ssh_connections': 50,
        'max_sftp_sessions': 30,
        'connection_timeout': 30,
        'idle_timeout': 300
    },
    'caching': {
        'response_cache_size': 2000,
        'response_cache_ttl': 600,
        'profile_cache_ttl': 300
    },
    'resource_limits': {
        'max_memory_mb': 2048,
        'max_concurrent_operations': 100,
        'max_per_profile': 20
    },
    'monitoring': {
        'metrics_collection': True,
        'health_check_interval': 30,
        'performance_monitoring': True
    }
}
```

### Load Balancing

Implement load balancing for high-availability deployments.

```python
class LoadBalancer:
    def __init__(self, servers: List[str]):
        self.servers = servers
        self.current_index = 0
        self.health_status = {server: True for server in servers}
    
    def get_next_server(self) -> str:
        """Get next available server using round-robin."""
        available_servers = [s for s in self.servers if self.health_status[s]]
        
        if not available_servers:
            # All servers down, reset health status
            self.health_status = {server: True for server in self.servers}
            available_servers = self.servers
        
        server = available_servers[self.current_index % len(available_servers)]
        self.current_index += 1
        return server
    
    def mark_server_unhealthy(self, server: str):
        """Mark a server as unhealthy."""
        if server in self.health_status:
            self.health_status[server] = False
    
    def mark_server_healthy(self, server: str):
        """Mark a server as healthy."""
        if server in self.health_status:
            self.health_status[server] = True
```

## Troubleshooting Performance Issues

### Common Performance Problems

1. **High Latency**
   - Check network connectivity
   - Verify SSH connection pooling
   - Review command execution timeouts

2. **Memory Leaks**
   - Monitor memory usage over time
   - Check for unclosed connections
   - Review cache cleanup procedures

3. **Connection Exhaustion**
   - Verify connection pool limits
   - Check for connection leaks
   - Review connection timeouts

4. **Cache Inefficiency**
   - Monitor cache hit rates
   - Adjust cache TTL values
   - Review cache eviction policies

### Performance Debugging

```python
async def debug_performance_issue(operation: str, profile_id: str):
    """Debug performance issues for specific operations."""
    print(f"Debugging performance for {operation} on {profile_id}")
    
    # Check connection pool status
    pool_stats = connection_pool.get_stats()
    print(f"Connection pool: {pool_stats}")
    
    # Check cache performance
    cache_stats = response_cache.get_stats()
    print(f"Cache performance: {cache_stats}")
    
    # Check resource usage
    resource_stats = resource_manager.get_resource_stats()
    print(f"Resource usage: {resource_stats}")
    
    # Run targeted benchmark
    benchmark = PerformanceBenchmark(server)
    if operation == "ssh.exec":
        result = await benchmark.run_ssh_benchmark(profile_id, iterations=10)
    elif operation == "sftp.transfer":
        result = await benchmark.run_sftp_benchmark(profile_id, iterations=5)
    
    print(f"Benchmark result: {result}")
```

## Next Steps

1. **Implement connection pooling** for SSH and SFTP
2. **Add response caching** for frequently requested operations
3. **Set up performance monitoring** and alerting
4. **Run performance benchmarks** to establish baselines
5. **Optimize configuration** based on benchmark results
6. **Monitor production performance** and adjust as needed

For additional performance optimization techniques, refer to the [API documentation](API.md) and [deployment guide](DEPLOYMENT.md).
