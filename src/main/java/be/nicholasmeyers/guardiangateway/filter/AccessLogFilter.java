package be.nicholasmeyers.guardiangateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Profile("access_log")
@Component
public class AccessLogFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(AccessLogFilter.class);
    private final ReactiveStringRedisTemplate redisTemplate;

    public AccessLogFilter(ReactiveStringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long startTime = System.currentTimeMillis();

        return chain.filter(exchange)
                .doFinally(signalType -> {
                    log.debug("Request processing finished for path: {}", exchange.getRequest().getURI().getPath());
                })
                .then(Mono.defer(() -> {
                    long duration = System.currentTimeMillis() - startTime;

                    Map<String, String> logEntry = new HashMap<>();
                    logEntry.put("timestamp", Instant.now().toString());
                    logEntry.put("method", exchange.getRequest().getMethod().name());
                    logEntry.put("path", exchange.getRequest().getURI().getPath());
                    logEntry.put("client_ip", exchange.getRequest().getRemoteAddress() != null
                            ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown");
                    logEntry.put("status_code", String.valueOf(exchange.getResponse().getStatusCode() != null
                            ? exchange.getResponse().getStatusCode().value() : 0));
                    logEntry.put("duration_ms", String.valueOf(duration));

                    logEntry.put("user_agent", exchange.getRequest().getHeaders().getFirst("User-Agent") != null
                            ? exchange.getRequest().getHeaders().getFirst("User-Agent") : "N/A");
                    logEntry.put("host", exchange.getRequest().getHeaders().getFirst("Host") != null
                            ? exchange.getRequest().getHeaders().getFirst("Host") : "N/A");

                    return redisTemplate.opsForStream().add("access_logs", logEntry)
                            .doOnSuccess(recordId -> log.info("Successfully added log entry to stream with ID: {}", recordId.getValue()))
                            .doOnError(e -> log.error("Failed to add log entry to Redis stream 'access_logs': {}", e.getMessage(), e))
                            .then()
                            .subscribeOn(Schedulers.boundedElastic());
                }));
    }
}
