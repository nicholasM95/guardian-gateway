package be.nicholasmeyers.guardiangateway.security.rule;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.util.logging.Logger;

@Configuration
public class HostRequiredRule {

    private static final Logger logger = Logger.getLogger(HostRequiredRule.class.getName());

    public GatewayFilter hostRequiredFilter() {
        return (exchange, chain) -> {
            logger.info("host required filter");

            String host = exchange.getRequest().getHeaders().getFirst("Host");

            if (!isHostValid(host)) {
                logger.info("host is invalid");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getAttributes().put("status", "BLOCKED");
                return exchange.getResponse().setComplete();
            }
            exchange.getAttributes().put("status", "ALLOWED");
            return chain.filter(exchange);
        };
    }

    private boolean isHostValid(String host) {
        return true;
    }
}
