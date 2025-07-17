package be.nicholasmeyers.guardiangateway.config;

import be.nicholasmeyers.guardiangateway.cert.CertStore;
import be.nicholasmeyers.guardiangateway.cert.CertUpdateEvent;
import be.nicholasmeyers.guardiangateway.cert.CertificateInfo;
import be.nicholasmeyers.guardiangateway.https.ReloadingSslContextSupplier;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import reactor.netty.http.server.HttpServer;

import javax.net.ssl.SSLException;
import java.util.List;

@Configuration
public class MultiPortConfig {

    private final ReloadingSslContextSupplier supplier;
    private final CertStore certStore;

    public MultiPortConfig(CertStore certStore) {
        this.supplier = new ReloadingSslContextSupplier();
        this.certStore = certStore;
    }

    @Bean
    @Primary
    public NettyReactiveWebServerFactory webServerFactory(HttpHandler httpHandler) {
        NettyReactiveWebServerFactory factory = new NettyReactiveWebServerFactory();
        factory.setPort(443);

        factory.addServerCustomizers(httpServer ->
                httpServer.secure(sslContextSpec ->
                        sslContextSpec.sslContext(supplier.get())
                )
        );

        HttpServer.create()
                .port(80)
                .handle(new ReactorHttpHandlerAdapter(httpHandler))
                .bindNow();

        return factory;
    }

    @EventListener
    public void handleCertificatesReloaded(CertUpdateEvent event) {
        if (!certStore.isEmpty()) {
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

            try {
                SslContext sslContext = builder.build();
                supplier.updateSslContext(sslContext);
            } catch (SSLException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
