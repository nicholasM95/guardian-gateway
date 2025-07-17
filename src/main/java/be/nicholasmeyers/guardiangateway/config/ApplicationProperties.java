package be.nicholasmeyers.guardiangateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

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

    public void setConfig(List<ApplicationConfig> config) {
        this.config = config;
    }
}
