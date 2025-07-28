package be.nicholasmeyers.guardiangateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    private List<ApplicationConfig> config;

    public List<ApplicationConfig> getConfig() {
        if (config == null) {
            return List.of();
        }
        return config;
    }

    public Optional<ApplicationConfig> findConfigByHost(String host) {
        for (ApplicationConfig config : getConfig()) {
            if (config.getHost().equalsIgnoreCase(host)) {
                return Optional.of(config);
            }
        }
        return Optional.empty();
    }

    public void setConfig(List<ApplicationConfig> config) {
        this.config = config;
    }
}
