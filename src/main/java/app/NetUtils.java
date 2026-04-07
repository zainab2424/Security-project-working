package app;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.Socket;

/*
 * NetUtils provides simple JSON send/receive helpers for socket communication.
 * Messages are sent one JSON object per line.
 */
public final class NetUtils {
    private NetUtils() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /* Serializes an object to JSON and writes it to the socket. */
    public static void sendJson(Socket s, Object obj) throws IOException {
        String json = MAPPER.writeValueAsString(obj);
        BufferedWriter w = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
        w.write(json);
        w.write("\n");
        w.flush();
    }

    /* Reads one JSON line from the socket and converts it to the requested class. */
    public static <T> T readJson(Socket s, Class<T> cls) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String line = r.readLine();
        if (line == null) throw new EOFException("Socket closed");
        return MAPPER.readValue(line, cls);
    }
}
