package be.nicholasmeyers.guardiangateway.service;

import be.nicholasmeyers.guardiangateway.config.DirectoryPropertiesConfig;
import be.nicholasmeyers.guardiangateway.event.LoadExistingCertificatesDoneEvent;
import be.nicholasmeyers.guardiangateway.repository.CertificateEntity;
import be.nicholasmeyers.guardiangateway.repository.CertificateRepository;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

@Service
public class LoadExistingCertificatesService {

    private static final Logger log = LoggerFactory.getLogger(LoadExistingCertificatesService.class);

    private final DirectoryPropertiesConfig directoryPropertiesConfig;
    private final CertificateRepository certificateRepository;
    private final ApplicationEventPublisher applicationEventPublisher;

    public LoadExistingCertificatesService(DirectoryPropertiesConfig directoryPropertiesConfig, CertificateRepository certificateRepository, ApplicationEventPublisher applicationEventPublisher) {
        this.directoryPropertiesConfig = directoryPropertiesConfig;
        this.certificateRepository = certificateRepository;
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public void loadExistingCertificates() {
        log.info("Loading existing certificates");
        List<String> existingDomainNames = getExistingDomainNames();
        existingDomainNames.forEach(domain -> {
            log.info("Found existing certificate for domain: {}", domain);
            try {
                Path domainDir = Paths.get(directoryPropertiesConfig.certificatesPath(), domain);
                Path certPath = domainDir.resolve("certificate.crt");
                Path keyPath = domainDir.resolve("private.key");

                if (Files.exists(certPath) && Files.exists(keyPath)) {
                    loadCertificateFromFile(domain, certPath, keyPath);
                }
            } catch (Exception e) {
                log.warn("Failed to load existing certificate for {} : {}", domain, e.getMessage());
            }
        });
        applicationEventPublisher.publishEvent(new LoadExistingCertificatesDoneEvent());
    }

    private List<String> getExistingDomainNames() {
        Path dir = Paths.get(directoryPropertiesConfig.certificatesPath());

        try (Stream<Path> stream = Files.list(dir)) {
            return stream
                    .filter(Files::isDirectory)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .toList();
        } catch (IOException e) {
            log.error("Error listing certificates", e);
            return List.of();
        }
    }

    private void loadCertificateFromFile(String domain, Path certPath, Path keyPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificateChain;
        try (InputStream certStream = Files.newInputStream(certPath)) {
            certificateChain = cf.generateCertificates(certStream).stream()
                    .map(cert -> (X509Certificate) cert)
                    .toList();
        }

        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("Certificate file is empty or invalid");
        }

        X509Certificate leafCert = certificateChain.getFirst();

        PrivateKey privateKey;
        try (Reader keyReader = new BufferedReader(new FileReader(keyPath.toFile()));
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            if (object == null) throw new IllegalArgumentException("Private key file is empty or invalid");

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof PEMKeyPair pemKeyPair) {
                PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
                privateKey = converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PrivateKeyInfo privateKeyInfo) {
                privateKey = converter.getPrivateKey(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("Unsupported key format: " + object.getClass());
            }
        }

        KeyPair keyPair = new KeyPair(leafCert.getPublicKey(), privateKey);

        CertificateEntity certInfo = new CertificateEntity(
                domain,
                leafCert,
                keyPair,
                certificateChain,
                leafCert.getNotAfter().toInstant()
        );

        certificateRepository.save(certInfo);
        log.info("Loaded certificate and full chain from file for domain: {}", domain);
    }
}
