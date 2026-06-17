package be.nicholasmeyers.guardiangateway.event;

import org.springframework.context.ApplicationEvent;

public class LoadExistingCertificatesDoneEvent  extends ApplicationEvent {

    public LoadExistingCertificatesDoneEvent() {
        super(true);
    }
}
