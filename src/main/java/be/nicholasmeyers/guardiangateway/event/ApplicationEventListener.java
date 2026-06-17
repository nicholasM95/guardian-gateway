package be.nicholasmeyers.guardiangateway.event;

import be.nicholasmeyers.guardiangateway.config.MultiPortConfig;
import be.nicholasmeyers.guardiangateway.service.LoadExistingCertificatesService;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;

@Component
public class ApplicationEventListener {

    private final LoadExistingCertificatesService loadExistingCertificatesService;
    private final MultiPortConfig multiPortConfig;

    public ApplicationEventListener(LoadExistingCertificatesService loadExistingCertificatesService, MultiPortConfig multiPortConfig) {
        this.loadExistingCertificatesService = loadExistingCertificatesService;
        this.multiPortConfig = multiPortConfig;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void handleApplicationReadyEvent() {
        loadExistingCertificatesService.loadExistingCertificates();
    }

    @EventListener(LoadExistingCertificatesDoneEvent.class)
    public void handleLoadExistingCertificatesDoneEvent() {
        multiPortConfig.updateSslContext();
        try {
            multiPortConfig.startHttpsServer();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }
}
