package be.nicholasmeyers.guardiangateway.certbot;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;
import java.util.logging.Logger;

@RestController
@RequestMapping("/.well-known/acme-challenge")
public class CertController {

    private static final Logger logger = Logger.getLogger(CertController.class.getName());

    private final ChallengeStore challengeStore;

    public CertController(ChallengeStore challengeStore) {
        this.challengeStore = challengeStore;
    }

    @GetMapping("/{token}")
    public String getChallenge(@PathVariable String token) {
        Optional<String> authorization = challengeStore.get(token);
        if (authorization.isPresent()) {
            logger.info("Serving ACME challenge for token");
            return authorization.get();
        } else {
            logger.warning("ACME challenge token not found");
            throw new RuntimeException("Token not found");
        }
    }
}
