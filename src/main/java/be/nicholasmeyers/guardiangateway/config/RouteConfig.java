package be.nicholasmeyers.guardiangateway.config;

import be.nicholasmeyers.guardiangateway.security.rule.HostRequiredRule;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static be.nicholasmeyers.guardiangateway.config.RouteType.PROXY;

@Configuration
public class RouteConfig {

    private final HostRequiredRule hostRequiredRule;

    public RouteConfig(HostRequiredRule hostRequiredRule) {
        this.hostRequiredRule = hostRequiredRule;
    }

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder, ApplicationProperties applicationProperties) {
        RouteLocatorBuilder.Builder routes = builder.routes();

        applicationProperties.getConfig().forEach(config -> {
            if (PROXY.equals(config.getType())) {
                routes.route(config.getName(), r -> r
                        .host(config.getHost())
                        .filters(f -> f
                                .preserveHostHeader()
                                .addRequestHeader("X-Forwarded-Host", config.getHost())
                                .filter(hostRequiredRule.hostRequiredFilter())
                        )
                        .uri(config.getService()));
            } else {
                routes.route(config.getName(), r -> r
                        .host(config.getHost())
                        .filters(f -> f
                                .filter(hostRequiredRule.hostRequiredFilter())
                                .redirect(301, config.getService()))
                        .uri("no://op"));
            }
        });

        return routes.build();
    }
}
