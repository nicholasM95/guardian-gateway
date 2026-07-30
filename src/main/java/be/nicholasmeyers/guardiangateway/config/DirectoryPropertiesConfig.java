package be.nicholasmeyers.guardiangateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "directory")
public record DirectoryPropertiesConfig(String certificatesPath) {
}
