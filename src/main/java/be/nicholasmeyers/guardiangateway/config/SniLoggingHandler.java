package be.nicholasmeyers.guardiangateway.config;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SniCompletionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SniLoggingHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SniLoggingHandler.class);


    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SniCompletionEvent) {
            SniCompletionEvent event = (SniCompletionEvent) evt;
            String hostname = event.hostname();
            if (event.isSuccess()) {
                log.info("SNI handshake succeeded, hostname: {}", hostname);
            } else {
                log.error("SNI handshake failed or hostname missing");
            }
        }
        super.userEventTriggered(ctx, evt);
    }
}
