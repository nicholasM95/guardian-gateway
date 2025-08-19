package be.nicholasmeyers.guardiangateway.config;

import be.nicholasmeyers.guardiangateway.cert.CertStore;
import be.nicholasmeyers.guardiangateway.cert.CertUpdateEvent;
import be.nicholasmeyers.guardiangateway.cert.CertificateInfo;
import be.nicholasmeyers.guardiangateway.https.DummySslContextGenerator;
import be.nicholasmeyers.guardiangateway.https.ReloadingSslContextSupplier;
import io.netty.handler.ssl.SniHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.DomainWildcardMappingBuilder;
import io.netty.util.Mapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import javax.net.ssl.SSLException;
import java.security.cert.X509Certificate;
import java.util.List;

@Configuration
public class MultiPortConfig {

    private static final Logger log = LoggerFactory.getLogger(MultiPortConfig.class);

    private final CertStore certStore;
    private final ApplicationProperties applicationProperties;
    private final ReloadingSslContextSupplier sslSupplier;
    private DisposableServer httpsServer;
    private final HttpHandler httpHandler;

    public MultiPortConfig(CertStore certStore, ApplicationProperties applicationProperties, HttpHandler httpHandler) {
        this.certStore = certStore;
        this.applicationProperties = applicationProperties;
        this.httpHandler = httpHandler;
        this.sslSupplier = new ReloadingSslContextSupplier();
    }

    @Bean
    @Primary
    public NettyReactiveWebServerFactory httpServerFactory() {
        NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
        factory.setPort(80);
        return factory;
    }

    @EventListener
    public void handleCertificatesReloaded(CertUpdateEvent event) throws SSLException {
        if (certStore.getAll().size() >= applicationProperties.getConfig().size()) {
            startHttpsServer();
        }

        updateSslContext();
    }

    private void startHttpsServer() throws SSLException {
        if (httpsServer != null) return;

        log.info("Starting HTTPS server on port 443...");

        SslContext defaultSsl = DummySslContextGenerator.create();
        DomainWildcardMappingBuilder<SslContext> mappingBuilder = new DomainWildcardMappingBuilder<>(defaultSsl);

        List<CertificateInfo> certs = certStore.getAll();
        for (CertificateInfo cert : certs) {
            mappingBuilder.add(cert.domain(), createSslContextForCert(cert));
        }

        Mapping<String, SslContext> sniMapping = mappingBuilder.build();

        httpsServer = HttpServer.create()
                .port(443)
                .doOnChannelInit((observer, channel, remoteAddress) -> {
                    channel.pipeline().addFirst(new SniLoggingHandler());
                    channel.pipeline().addFirst(new SniHandler(sniMapping));
                })
                .handle(new ReactorHttpHandlerAdapter(httpHandler))
                .bindNow();

    }

    private SslContext createSslContextForCert(CertificateInfo cert) throws SSLException {
        return SslContextBuilder
                .forServer(cert.keyPair().getPrivate(), cert.certificateChain().toArray(new X509Certificate[0]))
                .build();
    }

    private void updateSslContext() {
        if (certStore.isEmpty()) return;

        try {
            List<CertificateInfo> certs = certStore.getAll();

            SslContextBuilder builder = SslContextBuilder.forServer(
                    certs.getFirst().keyPair().getPrivate(),
                    certs.getFirst().certificate()
            );

            for (int i = 1; i < certs.size(); i++) {
                builder.keyManager(
                        certs.get(i).keyPair().getPrivate(),
                        certs.get(i).certificate()
                );
            }

            sslSupplier.updateSslContext(builder.build());
            log.info("SSL Context updated");
        } catch (SSLException e) {
            throw new RuntimeException("Failed to update SSL context", e);
        }
    }
}
