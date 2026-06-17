package be.nicholasmeyers.guardiangateway.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class CertificateMapRepository implements CertificateRepository {

    private static final Logger log = LoggerFactory.getLogger(CertificateMapRepository.class);
    private final Map<String, CertificateEntity> certificateMap = new HashMap<>();

    @Override
    public void save(CertificateEntity certificateEntity) {
        if (certificateMap.containsKey(certificateEntity.getDomain())) {
            log.warn("Certificate already exists for domain: {}", certificateEntity.getDomain());
        }
        certificateMap.put(certificateEntity.getDomain(), certificateEntity);
    }

    @Override
    public List<CertificateEntity> findAll() {
        return certificateMap.values().stream().toList();
    }
}
