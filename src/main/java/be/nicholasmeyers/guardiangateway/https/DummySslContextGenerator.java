package be.nicholasmeyers.guardiangateway.https;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

public class DummySslContextGenerator {
    public static SslContext create() {
        try {
            SelfSignedCertificate ssc = new SelfSignedCertificate("localhost");

            return SslContextBuilder
                    .forServer(ssc.certificate(), ssc.privateKey())
                    .build();

        } catch (CertificateException | SSLException e) {
            throw new RuntimeException("Failed to generate dummy SSL context", e);
        }
    }
}
