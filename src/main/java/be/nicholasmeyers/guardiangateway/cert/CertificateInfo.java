package be.nicholasmeyers.guardiangateway.cert;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

public record CertificateInfo(String domain, X509Certificate certificate, KeyPair keyPair, List<X509Certificate> certificateChain,
                              Instant expiryDate, LocalDateTime lastLoaded) {
}