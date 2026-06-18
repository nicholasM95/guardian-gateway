package be.nicholasmeyers.guardiangateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((exchange, ex) -> {
                            log.info("Blocked request from {}", exchange.getRequest().getRemoteAddress());
                            exchange.getAttributes().put("status", "BLOCKED");
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler((exchange, denied) -> {
                            log.info("Blocked request from {}", exchange.getRequest().getRemoteAddress());
                            exchange.getAttributes().put("status", "BLOCKED");
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                )
                .authorizeExchange(exchanges -> exchanges
                        .matchers(new IpHostMatcher()).denyAll()
                        .anyExchange().permitAll()
                )
                .build();
    }
}
