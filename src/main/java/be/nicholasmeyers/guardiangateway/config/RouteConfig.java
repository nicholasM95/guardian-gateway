package be.nicholasmeyers.guardiangateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder, ApplicationProperties applicationProperties) {
        RouteLocatorBuilder.Builder routes = builder.routes();

        applicationProperties.getConfig().forEach(config -> {
            routes.route(config.getName(), r -> r
                    .host(config.getHost())
                    .filters(f -> f
                            .preserveHostHeader()
                            .addRequestHeader("X-Forwarded-Host", config.getHost())
                    )
                    .uri(config.getService()));
        });

        return routes.build();
    }
}
