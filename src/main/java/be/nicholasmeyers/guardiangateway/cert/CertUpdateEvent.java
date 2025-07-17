package be.nicholasmeyers.guardiangateway.cert;

import org.springframework.context.ApplicationEvent;

public class CertUpdateEvent extends ApplicationEvent {

    public CertUpdateEvent(CertificateInfo certificateInfo) {
        super(certificateInfo);
    }
}
