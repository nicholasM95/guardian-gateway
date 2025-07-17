package be.nicholasmeyers.guardiangateway.cert;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CertStore {
    private final ConcurrentHashMap<String, CertificateInfo> domainCertificates = new ConcurrentHashMap<>();

    public Optional<CertificateInfo> get(String host) {
        return Optional.ofNullable(domainCertificates.get(host));
    }

    public void put(String host, CertificateInfo info) {
        domainCertificates.put(host, info);
    }

    public boolean contains(String host) {
        return domainCertificates.containsKey(host);
    }

    public boolean isEmpty() {
        return domainCertificates.isEmpty();
    }

    public List<CertificateInfo> getAll() {
        return new ArrayList<>(domainCertificates.values());
    }
}
