package web.bridge;

import app.NetUtils;
import app.Protocol.Msg;

import java.io.File;
import java.net.Socket;
import java.nio.file.Files;

public class BridgeClient {
    private static final String GATEWAY_SECRET = loadGatewaySecret();

    private static String loadGatewaySecret() {
        try {
            File f = new File("web-data/gateway-secret.txt");
            if (!f.exists()) return null;
            return Files.readString(f.toPath()).trim();
        } catch (Exception e) {
            return null;
        }
    }

    private final String host;
    private final int port;

    public BridgeClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public Msg send(Msg req) throws Exception {
        req.gatewayToken = GATEWAY_SECRET;
        try (Socket s = new Socket(host, port)) {
            NetUtils.sendJson(s, req);
            return NetUtils.readJson(s, Msg.class);
        }
    }
}