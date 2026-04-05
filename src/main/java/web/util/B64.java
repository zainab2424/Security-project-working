package web.util;

import java.util.Base64;

public final class B64 {
    private B64() {}
    public static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static byte[] b64d(String s) { return Base64.getDecoder().decode(s); }
}

