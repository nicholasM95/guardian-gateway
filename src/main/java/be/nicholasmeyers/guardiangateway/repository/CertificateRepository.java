package be.nicholasmeyers.guardiangateway.repository;

import java.util.List;

public interface CertificateRepository {

    void save(CertificateEntity certificateEntity);

    List<CertificateEntity> findAll();
}
