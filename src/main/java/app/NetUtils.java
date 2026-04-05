package app;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.Socket;

public final class NetUtils {
    private NetUtils() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void sendJson(Socket s, Object obj) throws IOException {
        String json = MAPPER.writeValueAsString(obj);
        BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
        w.write(json);
        w.write("\n");
        w.flush();
    }

    public static <T> T readJson(Socket s, Class<T> cls) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String line = r.readLine();
        if (line == null) throw new EOFException("Socket closed");
        return MAPPER.readValue(line, cls);
    }
}
