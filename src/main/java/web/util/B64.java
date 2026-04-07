package web.util;

import java.util.Base64;

// Small helper for Base64 encoding and decoding.
public final class B64 {
    private B64() {}

    // Encodes bytes to Base64.
    public static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    // Decodes a Base64 string into bytes.
    public static byte[] b64d(String s) { return Base64.getDecoder().decode(s); }
}
