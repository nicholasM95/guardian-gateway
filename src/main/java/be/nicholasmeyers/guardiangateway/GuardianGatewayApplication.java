package be.nicholasmeyers.guardiangateway;

import be.nicholasmeyers.guardiangateway.config.DirectoryPropertiesConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(DirectoryPropertiesConfig.class)
public class GuardianGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GuardianGatewayApplication.class, args);
    }
}
