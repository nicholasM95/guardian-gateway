package be.nicholasmeyers.guardiangateway.https;

import io.netty.handler.ssl.SslContext;

import java.util.function.Supplier;

public class ReloadingSslContextSupplier implements Supplier<SslContext> {
    private volatile SslContext sslContext;

    public ReloadingSslContextSupplier() {
    }

    public void updateSslContext(SslContext newContext) {
        this.sslContext = newContext;
    }

    @Override
    public SslContext get() {
        if (sslContext == null) {
            return DummySslContextGenerator.create();
        }
        return sslContext;
    }
}
