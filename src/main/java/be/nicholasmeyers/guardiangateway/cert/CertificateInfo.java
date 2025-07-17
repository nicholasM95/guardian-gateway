package be.nicholasmeyers.guardiangateway.cert;

import javax.net.ssl.SSLContext;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;

public record CertificateInfo(String domain, X509Certificate certificate, KeyPair keyPair, SSLContext sslContext,
                              Instant expiryDate, LocalDateTime lastLoaded) {
}