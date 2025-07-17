package be.nicholasmeyers.guardiangateway.certbot;

import be.nicholasmeyers.guardiangateway.config.ApplicationConfig;
import be.nicholasmeyers.guardiangateway.config.ApplicationProperties;
import be.nicholasmeyers.guardiangateway.cert.CertStore;
import be.nicholasmeyers.guardiangateway.cert.CertUpdateEvent;
import be.nicholasmeyers.guardiangateway.cert.CertificateInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Component
public class CertManager {

    private static final Logger logger = Logger.getLogger(CertManager.class.getName());
    private final ApplicationEventPublisher eventPublisher;
    private final ApplicationProperties properties;
    private final ChallengeStore challengeStore;
    private final CertStore certStore;

    @Value("${acme.email:}")
    private String acmeEmail;
    @Value("${acme.staging:false}")
    private boolean useStaging;
    @Value("${acme.account-key-path:/app/data/account.key}")
    private String accountKeyPath;
    @Value("${acme.certificates-path:/app/data/certificates}")
    private String certificatesPath;
    @Value("${acme.renewal-days-before:30}")
    private int renewalDaysBefore;
    private ScheduledExecutorService scheduler;
    private Session session;
    private Account account;

    public CertManager(ApplicationEventPublisher eventPublisher, ApplicationProperties properties,
                       ChallengeStore challengeStore, CertStore certStore) {
        this.eventPublisher = eventPublisher;
        this.properties = properties;
        this.challengeStore = challengeStore;
        this.certStore = certStore;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void initialize() {
        try {
            Files.createDirectories(Paths.get(certificatesPath));
            Files.createDirectories(Paths.get(accountKeyPath).getParent());

            initializeACME();
            loadExistingCertificates();
            requestMissingCertificates();
            startRenewalScheduler();

            logger.info("ACME Certificate Manager initialized successfully");
        } catch (Exception e) {
            logger.severe("Failed to initialize ACME Certificate Manager: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void initializeACME() throws Exception {
        KeyPair accountKeyPair = loadOrCreateAccountKeyPair();

        String acmeUrl = useStaging ?
                "acme://letsencrypt.org/staging" :
                "acme://letsencrypt.org";

        session = new Session(acmeUrl);

        AccountBuilder accountBuilder = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKeyPair);

        if (acmeEmail != null && !acmeEmail.isEmpty()) {
            accountBuilder.addContact("mailto:" + acmeEmail);
        }

        account = accountBuilder.create(session);
        logger.info("ACME account created/loaded successfully");
    }

    private KeyPair loadOrCreateAccountKeyPair() throws Exception {
        Path keyPath = Paths.get(accountKeyPath);

        if (Files.exists(keyPath)) {
            logger.info("Loading existing account key pair");
            try (FileReader fr = new FileReader(keyPath.toFile())) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            logger.info("Creating new account key pair");
            KeyPair keyPair = KeyPairUtils.createKeyPair(2048);

            try (FileWriter fw = new FileWriter(keyPath.toFile())) {
                KeyPairUtils.writeKeyPair(keyPair, fw);
            }

            return keyPair;
        }
    }

    private void loadExistingCertificates() {
        properties.getConfig().stream().map(ApplicationConfig::getHost)
                .forEach(host -> {
                    try {
                        Path domainDir = Paths.get(certificatesPath, host);
                        Path certPath = domainDir.resolve("certificate.crt");
                        Path keyPath = domainDir.resolve("private.key");

                        if (Files.exists(certPath) && Files.exists(keyPath)) {
                            loadCertificateFromFile(host, certPath, keyPath);
                        }
                    } catch (Exception e) {
                        logger.warning("Failed to load existing certificate for " + host + ": " + e.getMessage());
                    }
                });
    }

    private void loadCertificateFromFile(String domain, Path certPath, Path keyPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        try (InputStream certStream = Files.newInputStream(certPath)) {
            certificate = (X509Certificate) cf.generateCertificate(certStream);
        }

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

        KeyPair keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
        SSLContext sslContext = createSSLContext(certificate, keyPair);

        CertificateInfo certInfo = new CertificateInfo(
                domain,
                certificate,
                keyPair,
                sslContext,
                certificate.getNotAfter().toInstant(),
                LocalDateTime.now()
        );

        certStore.put(domain, certInfo);
        eventPublisher.publishEvent(new CertUpdateEvent(certInfo));

        logger.info("Loaded certificate from file for domain: " + domain);
    }

    private void requestMissingCertificates() {
        properties.getConfig().stream().map(ApplicationConfig::getHost)
                .forEach(host -> {
                    if (!certStore.contains(host)) {
                        logger.info("Requesting new certificate for domain: " + host);
                        requestCertificateAsync(host);
                    }
                });
    }

    private void requestCertificateAsync(String domain) {
        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.submit(() -> {
            try {
                requestCertificate(domain);
            } catch (Exception e) {
                logger.severe("Failed to request certificate for " + domain + ": " + e.getMessage());
            }
        });
    }

    private void requestCertificate(String domain) throws Exception {
        logger.info("Starting certificate request for domain: " + domain);

        Order order = account.newOrder().domain(domain).create();

        for (Authorization auth : order.getAuthorizations()) {
            processAuthorization(auth);
        }

        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

        CSRBuilder csrBuilder = new CSRBuilder();
        csrBuilder.addDomain(domain);
        csrBuilder.sign(domainKeyPair);

        order.execute(csrBuilder.getEncoded());

        while (order.getStatus() != Status.VALID) {
            if (order.getStatus() == Status.INVALID) {
                throw new RuntimeException("Certificate order failed for domain: " + domain);
            }
            Thread.sleep(3000);
            order.update();
        }

        Certificate certificate = order.getCertificate();
        X509Certificate x509Certificate = certificate.getCertificate();

        saveCertificate(domain, x509Certificate, domainKeyPair);

        SSLContext sslContext = createSSLContext(x509Certificate, domainKeyPair);

        CertificateInfo certInfo = new CertificateInfo(
                domain,
                x509Certificate,
                domainKeyPair,
                sslContext,
                x509Certificate.getNotAfter().toInstant(),
                LocalDateTime.now()
        );

        certStore.put(domain, certInfo);
        eventPublisher.publishEvent(new CertUpdateEvent(certInfo));
        logger.info("Certificate successfully obtained and stored for domain: " + domain);
    }

    private void processAuthorization(Authorization auth) throws Exception {
        logger.info("Processing authorization for domain: " + auth.getIdentifier().getDomain());

        Optional<Http01Challenge> challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge.isEmpty()) {
            throw new RuntimeException("No HTTP-01 challenge found");
        }

        String domain = auth.getIdentifier().getDomain();
        String token = challenge.get().getToken();
        String authorization = challenge.get().getAuthorization();

        challengeStore.add(token, authorization);

        logger.info("Challenge stored for domain " + domain + " with token: " + token);

        challenge.get().trigger();

        while (challenge.get().getStatus() != Status.VALID) {
            if (challenge.get().getStatus() == Status.INVALID) {
                throw new RuntimeException("Challenge failed for domain: " + domain);
            }
            Thread.sleep(3000);
            challenge.get().update();
        }

        challengeStore.remove(token);

        logger.info("Challenge completed successfully for domain: " + domain);
    }

    private void saveCertificate(String domain, X509Certificate certificate, KeyPair keyPair) throws Exception {
        Path domainDir = Paths.get(certificatesPath, domain);
        Files.createDirectories(domainDir);

        Path certPath = domainDir.resolve("certificate.crt");
        try (FileWriter fw = new FileWriter(certPath.toFile())) {
            writeCertificatePem(certificate, fw);
        }

        Path keyPath = domainDir.resolve("private.key");
        try (FileWriter fw = new FileWriter(keyPath.toFile())) {
            KeyPairUtils.writeKeyPair(keyPair, fw);
        }
        logger.info("Certificate and key saved for domain: " + domain);
    }

    private void writeCertificatePem(X509Certificate certificate, Writer writer) throws IOException, CertificateEncodingException {
        writer.write("-----BEGIN CERTIFICATE-----\n");
        writer.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()));
        writer.write("\n-----END CERTIFICATE-----\n");
        writer.flush();
    }


    private SSLContext createSSLContext(X509Certificate certificate, KeyPair keyPair) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        keyStore.setKeyEntry("key", keyPair.getPrivate(),
                "password".toCharArray(), new X509Certificate[]{certificate});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }

    private void startRenewalScheduler() {
        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            logger.info("Checking certificates for renewal...");

            properties.getConfig().stream().map(ApplicationConfig::getHost)
                    .forEach(host -> {
                        Optional<CertificateInfo> certInfo = certStore.get(host);
                        if (certInfo.isPresent()) {
                            Instant renewalTime = certInfo.get().expiryDate()
                                    .minus(Duration.ofDays(renewalDaysBefore));

                            if (Instant.now().isAfter(renewalTime)) {
                                logger.info("Certificate for " + host + " needs renewal");
                                requestCertificateAsync(host);
                            }
                        }
                    });
        }, 1, 24, TimeUnit.HOURS);
    }
}
