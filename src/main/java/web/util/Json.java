package web.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;

public final class Json {
    private Json() {}
    public static final ObjectMapper M = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static <T> T read(File f, Class<T> cls, T fallback) {
        try {
            if (!f.exists()) return fallback;
            return M.readValue(f, cls);
        } catch (Exception e) {
            return fallback;
        }
    }

    public static void write(File f, Object obj) {
        try {
            f.getParentFile().mkdirs();
            M.writeValue(f, obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

