package be.nicholasmeyers.guardiangateway.security.rule;

import be.nicholasmeyers.guardiangateway.config.ApplicationConfig;
import be.nicholasmeyers.guardiangateway.config.ApplicationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.util.List;

@Configuration
public class HostRequiredRule {

    private static final Logger log = LoggerFactory.getLogger(HostRequiredRule.class);
    private final ApplicationProperties applicationProperties;

    public HostRequiredRule(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    public GatewayFilter hostRequiredFilter() {
        return (exchange, chain) -> {
            log.info("host required filter");

            String host = exchange.getRequest().getHeaders().getFirst("Host") != null
                    ? exchange.getRequest().getHeaders().getFirst("Host") : "N/A";

            if (!isHostValid(host)) {
                log.info("host {} is invalid", host);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getAttributes().put("status", "BLOCKED");
                return exchange.getResponse().setComplete();
            }
            exchange.getAttributes().put("status", "ALLOWED");
            return chain.filter(exchange);
        };
    }

    private boolean isHostValid(String host) {
        List<String> allowedHosts = applicationProperties.getConfig().stream().map(ApplicationConfig::getHost).toList();
        return allowedHosts.contains(host);
    }
}
