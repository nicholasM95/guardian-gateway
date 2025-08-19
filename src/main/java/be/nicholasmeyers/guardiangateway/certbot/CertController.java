package be.nicholasmeyers.guardiangateway.certbot;

import be.nicholasmeyers.guardiangateway.config.ApplicationConfig;
import be.nicholasmeyers.guardiangateway.config.ApplicationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private final ChallengeStore challengeStore;
    private final ApplicationProperties applicationProperties;
    private final WebClient webClient;

    public CertController(ChallengeStore challengeStore, ApplicationProperties applicationProperties, WebClient.Builder webClientBuilder) {
        this.challengeStore = challengeStore;
        this.applicationProperties = applicationProperties;
        this.webClient = webClientBuilder.build();
    }

    @GetMapping("/{token}")
    public Mono<String> getChallenge(@RequestHeader Map<String, String> headers, @PathVariable String token) {
        Optional<String> host = Optional.ofNullable(headers.get("host"));
        Optional<String> authorization = challengeStore.get(token);
        if (authorization.isPresent()) {
            log.info("Serving ACME challenge for token");
            return Mono.just(authorization.get());
        } else {
            if (host.isPresent()) {
                return getChallengeFromUpstream(host.get(), token);
            }
            log.warn("ACME challenge token not found");
            throw new RuntimeException("Token not found");
        }
    }

    private Mono<String> getChallengeFromUpstream(String host, String token) {
        log.info("Serving ACME challenge for token from upstream");
        Optional<ApplicationConfig> config = applicationProperties.findConfigByHost(host);
        if (config.isPresent()) {
            String service = config.get().getService();
            service = service.replace("https://", "");
            service = service.replace("http://", "");
            String url = "http://" + service + "/.well-known/acme-challenge/" + token;
            return webClient.get()
                    .uri(url)
                    .retrieve()
                    .bodyToMono(String.class)
                    .doOnSubscribe(sub -> log.info("Fetching challenge from upstream: {}", url))
                    .doOnError(err -> log.error("Failed to fetch challenge from upstream: {}", err.getMessage()));
        } else {
            log.warn("ACME challenge upstream not found: application config not found");
            return Mono.just("");
        }
    }
}
