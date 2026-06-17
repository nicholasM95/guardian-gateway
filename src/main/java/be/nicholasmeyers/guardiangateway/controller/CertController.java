package be.nicholasmeyers.guardiangateway.controller;

import be.nicholasmeyers.guardiangateway.config.ApplicationConfig;
import be.nicholasmeyers.guardiangateway.config.ApplicationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/.well-known/acme-challenge")
public class CertController {

    private static final Logger log = LoggerFactory.getLogger(CertController.class);

    private final ApplicationProperties applicationProperties;
    private final WebClient webClient;

    public CertController(ApplicationProperties applicationProperties, WebClient webClient) {
        this.applicationProperties = applicationProperties;
        this.webClient = webClient;
    }

    @GetMapping("/{token}")
    public Mono<String> getChallenge(@RequestHeader Map<String, String> headers, @PathVariable String token) {
        Optional<String> host = Optional.ofNullable(headers.get("host"));
        log.info("Challenge requested for token: {}", token);
        log.info("Headers: {}", headers);

        Mono<String> challenge = getChallengeFromGuardianCertManager(token);
        if (challenge.equals(Mono.empty())) {
            if (host.isPresent()) {
                challenge = getChallengeFromUpstream("", token);
                if (challenge.equals(Mono.empty())) {
                    return Mono.empty();
                }
            } else {
                log.warn("No host header found in request");
                return Mono.empty();
            }
        }
        return challenge;
    }

    private Mono<String> getChallengeFromGuardianCertManager(String token) {
        log.info("Serving ACME challenge for token from guardian cert manager");
        return webClient.get()
                .uri("http://guardian-cert-manager:8080/api/v1/acme-challenge/" + token)
                .retrieve()
                .bodyToMono(String.class)
                .doOnSubscribe(_ -> log.info("Fetching challenge from guardian cert manager"));
    }

    private Mono<String> getChallengeFromUpstream(String host, String token) {
        log.info("Serving ACME challenge for token from upstream");
        Optional<ApplicationConfig> config = applicationProperties.findConfigByHost(host);
        if (config.isPresent()) {
            String service = config.get().getService();
            service = service.replace("https://", "");
            service = service.replace("http://", "");
            service = service.replace(":443", ":80");
            String url = "http://" + service + "/.well-known/acme-challenge/" + token;
            return webClient.get()
                    .uri(url)
                    .header("Host", host)
                    .retrieve()
                    .onStatus(status -> status.value() == 404, response -> {
                        log.warn("Resource not found (404): {} --- host: {}", url, host);
                        return Mono.empty();
                    })
                    .onStatus(HttpStatusCode::isError, response -> {
                        log.error("Upstream returned error status {} for: {} --- host: {}",
                                response.statusCode().value(), url, host);
                        return Mono.empty();
                    })
                    .bodyToMono(String.class)
                    .doOnSubscribe(sub -> log.info("Fetching challenge from upstream: {} --- host: {}", url, host));
        } else {
            log.warn("ACME challenge upstream not found: application config not found");
            return Mono.just("");
        }
    }
}
