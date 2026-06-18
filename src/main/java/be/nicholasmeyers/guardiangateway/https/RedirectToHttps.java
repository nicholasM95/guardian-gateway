package be.nicholasmeyers.guardiangateway.https;

import be.nicholasmeyers.guardiangateway.config.ApplicationConfig;
import be.nicholasmeyers.guardiangateway.config.ApplicationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import org.springframework.web.server.WebFilter;
import org.springframework.web.util.UriComponentsBuilder;


import java.net.URI;
import java.util.List;

@Component
public class RedirectToHttps {
    private static final Logger log = LoggerFactory.getLogger(RedirectToHttps.class);

    private final ApplicationProperties applicationProperties;

    public RedirectToHttps(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    @Bean
    public WebFilter httpsRedirectFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String path = request.getURI().getPath();
            String host = exchange.getRequest().getHeaders().getFirst("Host") != null
                    ? exchange.getRequest().getHeaders().getFirst("Host") : "N/A";

            if (!isHostValid(host)) {
                log.info("Host {} is not allowed, so disable redirect", host);
                return chain.filter(exchange);
            }

            if (path.startsWith("/.well-known/acme-challenge")) {
                log.info("No redirect for /.well-known/acme-challenge");
                return chain.filter(exchange);
            } else if ("http".equals(request.getURI().getScheme())) {
                String httpsUrl = UriComponentsBuilder.fromUri(request.getURI())
                        .scheme("https")
                        .build()
                        .toString();

                log.info("Redirect to https: {}", httpsUrl);
                response.setStatusCode(HttpStatus.MOVED_PERMANENTLY);
                response.getHeaders().setLocation(URI.create(httpsUrl));
                return response.setComplete();
            }

            if ("https".equals(request.getURI().getScheme())) {
                response.getHeaders().add("Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains; preload");
            }
            return chain.filter(exchange);
        };
    }

    private boolean isHostValid(String host) {
        List<String> allowedHosts = applicationProperties.getConfig().stream().map(ApplicationConfig::getHost).toList();
        return allowedHosts.contains(host);
    }
}
