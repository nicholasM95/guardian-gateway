package be.nicholasmeyers.guardiangateway.config;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SniCompletionEvent;

import java.util.logging.Logger;

public class SniLoggingHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = Logger.getLogger(SniLoggingHandler.class.getName());

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SniCompletionEvent) {
            SniCompletionEvent event = (SniCompletionEvent) evt;
            String hostname = event.hostname();
            if (event.isSuccess()) {
                logger.info("SNI handshake succeeded, hostname: " + hostname);
            } else {
                logger.severe("SNI handshake failed or hostname missing");
            }
        }
        super.userEventTriggered(ctx, evt);
    }
}
