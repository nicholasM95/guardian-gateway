package be.nicholasmeyers.guardiangateway.certbot;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ChallengeStore {

    private final ConcurrentHashMap<String, String> pendingChallenges = new ConcurrentHashMap<>();

    public void add(String token, String authorization) {
        pendingChallenges.put(token, authorization);
    }

    public void remove(String token) {
        pendingChallenges.remove(token);
    }

    public Optional<String> get(String token) {
        return Optional.ofNullable(pendingChallenges.get(token));
    }

}
