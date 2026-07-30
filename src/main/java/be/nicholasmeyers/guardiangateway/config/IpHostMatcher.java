package be.nicholasmeyers.guardiangateway.config;

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

public class IpHostMatcher implements ServerWebExchangeMatcher {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$");
    private static final Pattern IPV6 = Pattern.compile("^\\[.*](:\\d+)?$");

    @Override
    public Mono<MatchResult> matches(ServerWebExchange exchange) {
        String host = exchange.getRequest().getHeaders().getFirst("Host");
        if (host != null && (IPV4.matcher(host).matches() || IPV6.matcher(host).matches())) {
            return MatchResult.match();
        }
        return MatchResult.notMatch();
    }
}
