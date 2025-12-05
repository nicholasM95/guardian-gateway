package be.nicholasmeyers.guardiangateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
public class GlobalCorsPreflightFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(GlobalCorsPreflightFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            log.info("Handling OPTIONS preflight request");

            exchange.getResponse().setStatusCode(HttpStatus.OK);
            exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
            exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "*");
            exchange.getResponse().getHeaders().add("Access-Control-Max-Age", "3600");

            return exchange.getResponse().setComplete();
        }

        log.info("Not an OPTIONS request, continuing...");
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
