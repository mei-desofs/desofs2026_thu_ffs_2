# Monitoring & Observability Setup

## Overview

This monitoring setup provides comprehensive observability for the Kryptos application, covering:
- **Metrics**: JVM, Process, HTTP requests via Micrometer + Prometheus
- **Health Checks**: Liveness and readiness probes via Spring Boot Actuator
- **Structured Logging**: JSON format for centralized log aggregation
- **Visualization**: Grafana dashboards for real-time monitoring

---

## Architecture

```
┌─────────────────────┐
│   Kryptos App       │
│  (Spring Boot)      │
│   - Micrometer      │ → /actuator/prometheus
│   - Logstash JSON   │ → Console/File (JSON)
└─────────────────────┘
         │
         ↓ (scrape 10s)
┌─────────────────────┐
│  Prometheus         │ (port 9090)
│  (metrics storage)  │ http://localhost:9090
└─────────────────────┘
         │
         ↓ (query)
┌─────────────────────┐
│  Grafana            │ (port 3000)
│  (dashboards)       │ http://localhost:3000
└─────────────────────┘
```

---

## Quick Start

### 1. Start with Docker Compose

```bash
cd backend
docker-compose up -d
```

**Services:**
- App: http://localhost:8080
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

### 2. Access Health Endpoints

```bash
# Health check
curl http://localhost:8080/actuator/health

# Readiness probe (K8s)
curl http://localhost:8080/actuator/health/readiness

# Liveness probe (K8s)
curl http://localhost:8080/actuator/health/liveness

# Prometheus metrics
curl http://localhost:8080/actuator/prometheus
```

### 3. Grafana Setup

1. Open http://localhost:3000
2. Login: `admin` / `admin` (default)
3. Add Prometheus data source:
   - URL: http://prometheus:9090
   - Click "Save & test"
4. Import dashboards:
   - Dashboard ID: 1860 (Node Exporter Full)
   - Dashboard ID: 3662 (Prometheus)

---

## Metrics Collected

### JVM Metrics
- `jvm_memory_used_bytes` - Memory usage
- `jvm_threads_live` - Thread count
- `jvm_gc_*` - Garbage collection

### Process Metrics
- `process_cpu_usage` - CPU usage
- `process_resident_memory_bytes` - Memory resident
- `process_uptime_seconds` - Uptime

### HTTP Metrics
- `http_server_requests_seconds` - Request latency (histogram)
- `http_server_requests_seconds_count` - Request count
- `http_server_requests_seconds_sum` - Total request time

### Spring Metrics
- `spring_boot_application_ready_time_ms` - Startup time
- `tomcat_sessions_active_current` - Active sessions

---

## Structured Logging (JSON)

All logs are output in JSON format for easy parsing and aggregation:

```json
{
  "@timestamp": "2026-06-15T22:30:00.123Z",
  "app": "kryptos",
  "environment": "dev",
  "level": "INFO",
  "logger_name": "com.kryptos.auth.AuthService",
  "message": "User login successful",
  "thread_name": "http-nio-8080-exec-1",
  "mdc": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "ip_address": "192.168.1.100"
  }
}
```

### Log Integration

For production, integrate with centralized logging:

```bash
# Send to ELK Stack
docker run -d --name logstash \
  -e "OUTPUT_ELASTICSEARCH_HOSTS=elasticsearch:9200" \
  docker.elastic.co/logstash/logstash:8.0.0

# Or send to SumoLogic/Splunk/Datadog (modify logback config)
```

---

## Key Features

### ✅ Health Checks
- Readiness: App is ready to serve requests
- Liveness: App is running (use for container restarts)
- Endpoint: `/actuator/health`

### ✅ Metrics
- 15s scrape interval (configurable)
- Histograms, counters, gauges
- MeterRegistry for custom metrics

### ✅ Logging
- JSON format (machine readable)
- File rotation: 10MB per file, 30-day retention
- Custom fields: app name, environment

### ✅ Security
- Actuator endpoints protected (by default)
- Metrics exposed at `/actuator/prometheus` (public read-only)
- Health details only for authenticated users

---

## Custom Metrics Example

Add custom metrics in your service:

```java
@Service
public class AuthService {
    private final MeterRegistry meterRegistry;

    public AuthService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public void login(String username) {
        // ... login logic
        Counter.builder("auth.login.success")
            .tag("username", username)
            .register(meterRegistry)
            .increment();
    }
}
```

Access at: `http://localhost:8080/actuator/metrics/auth.login.success`

---

## Prometheus Queries

### Request Rate (requests per minute)
```promql
rate(http_server_requests_seconds_count[1m])
```

### P95 Latency
```promql
histogram_quantile(0.95, rate(http_server_requests_seconds_bucket[5m]))
```

### Memory Usage
```promql
jvm_memory_used_bytes{area="heap"}
```

### Error Rate
```promql
rate(http_server_requests_seconds_count{status=~"5.."}[1m])
```

---

## Production Checklist

- [ ] Configure external log forwarding (Splunk, ELK, etc.)
- [ ] Set Grafana admin password (env var: `GRAFANA_PASSWORD`)
- [ ] Enable HTTPS for Prometheus/Grafana
- [ ] Configure alerting rules in Prometheus
- [ ] Set up PagerDuty/Slack notifications
- [ ] Configure log retention policy (30 days default)
- [ ] Test health probes with load testing
- [ ] Document runbooks for common alerts

---

## Troubleshooting

### Prometheus can't scrape app metrics
```bash
# Check app is responding
curl http://app:8080/actuator/prometheus

# Check Prometheus config
docker logs prometheus
```

### No logs appearing
```bash
# Check logback config loaded
tail -f /tmp/kryptos/spring.log

# Verify JSON output
docker logs kryptos_app | head -20
```

### Grafana can't connect to Prometheus
```bash
# Verify network
docker exec grafana ping prometheus

# Check data source URL: http://prometheus:9090
```

---

## References

- [Spring Boot Actuator](https://spring.io/guides/gs/actuator-service/)
- [Micrometer Prometheus](https://micrometer.io/docs/registry/prometheus)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)
- [Logstash Logback Encoder](https://github.com/logstash/logstash-logback-encoder)
