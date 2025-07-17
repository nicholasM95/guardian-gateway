package be.nicholasmeyers.guardiangateway.https;

import java.util.logging.Logger;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import org.springframework.web.server.WebFilter;
import org.springframework.web.util.UriComponentsBuilder;


import java.net.URI;

@Component
public class RedirectToHttps {
    private static final Logger logger = Logger.getLogger(RedirectToHttps.class.getName());

    @Bean
    public WebFilter httpsRedirectFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String path = request.getURI().getPath();

            if (path.startsWith("/.well-known/acme-challenge")) {
                logger.info("No redirect for /.well-known/acme-challenge");
                return chain.filter(exchange);
            } else if ("http".equals(request.getURI().getScheme())) {
                logger.info("Redirect to https");
                String httpsUrl = UriComponentsBuilder.fromUri(request.getURI())
                        .scheme("https")
                        .build()
                        .toString();

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
}
