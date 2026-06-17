package be.nicholasmeyers.guardiangateway.repository;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

public class CertificateEntity {

    private final String domain;
    private final X509Certificate certificate;
    private final KeyPair keyPair;
    private final List<X509Certificate> certificateChain;
    private final Instant expiryDate;

    public CertificateEntity(String domain, X509Certificate certificate, KeyPair keyPair, List<X509Certificate> certificateChain, Instant expiryDate) {
        this.domain = domain;
        this.certificate = certificate;
        this.keyPair = keyPair;
        this.certificateChain = certificateChain;
        this.expiryDate = expiryDate;
    }

    public String getDomain() {
        return domain;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }
}
