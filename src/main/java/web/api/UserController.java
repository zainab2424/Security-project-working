package web.api;

import app.Protocol.Msg;
import org.springframework.web.bind.annotation.*;
import web.bridge.BridgeClient;
import web.store.UserStore;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserStore userStore = new UserStore();
    private final BridgeClient bridge = new BridgeClient("127.0.0.1", 5050);

    private static final Set<String> ALLOWED_ROLES = Set.of("LAWYER", "CLIENT");
    private static final String PASSWORD_POLICY_ERROR =
            "Unlock key must be at least 6 characters and include 1 uppercase letter, 1 number, and 1 special character";

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String role = body.get("role");
        String unlockKey = body.get("unlockKey");
        String publicKeyB64 = body.get("publicKeyB64");
        String saltB64 = body.get("saltB64");
        String ivB64 = body.get("ivB64");
        String encPrivB64 = body.get("encPrivB64");

        if (username == null || role == null || unlockKey == null || publicKeyB64 == null ||
                saltB64 == null || ivB64 == null || encPrivB64 == null) {
            return Map.of("ok", false, "error", "Missing fields");
        }

        username = username.trim();
        role = role.trim().toUpperCase();

        if (username.isEmpty()) return Map.of("ok", false, "error", "Username required");
        if (!isValidUnlockKey(unlockKey)) {
            return Map.of("ok", false, "error", PASSWORD_POLICY_ERROR);
        }
        if (!username.matches("^[a-zA-Z0-9._-]{3,32}$")) {
            return Map.of("ok", false, "error", "Username must be 3-32 chars (letters/numbers/._-)");
        }
        if (!ALLOWED_ROLES.contains(role)) {
            return Map.of("ok", false, "error", "Invalid role");
        }

        // Prevent overwriting an existing user (stops role changes / key replacement)
        var existing = userStore.get(username);
        if (existing != null) {
            return Map.of("ok", false, "error", "Username already exists");
        }

        // Restrict LAWYER registrations
        if ("LAWYER".equals(role)) {
            String supplied = body.get("lawyerCode");
            if (supplied == null || supplied.isBlank()) {
                return Map.of("ok", false, "error", "Lawyer invite code required");
            }
            String expected = getLawyerRegCode();
            if (expected == null || expected.isBlank()) {
                return Map.of("ok", false, "error", "Lawyer registration not enabled on server");
            }
            if (!expected.equals(supplied.trim())) {
                return Map.of("ok", false, "error", "Invalid lawyer invite code");
            }
        }

        // Save in web store
        userStore.upsert(username, role, publicKeyB64, saltB64, ivB64, encPrivB64);

        // Register with socket server
        Msg reg = new Msg();
        reg.type = "REGISTER";
        reg.from = username;
        reg.publicKeyB64 = publicKeyB64;

        Msg resp = bridge.send(reg);
        if (!"REGISTER_OK".equals(resp.type)) {
            return Map.of("ok", false, "error", resp.error);
        }

        return Map.of("ok", true);
    }

    private boolean isValidUnlockKey(String unlockKey) {
        if (unlockKey == null || unlockKey.length() < 6) return false;
        boolean hasUppercase = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (int i = 0; i < unlockKey.length(); i++) {
            char ch = unlockKey.charAt(i);
            if (Character.isUpperCase(ch)) {
                hasUppercase = true;
            } else if (Character.isDigit(ch)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(ch)) {
                hasSpecial = true;
            }
        }

        return hasUppercase && hasDigit && hasSpecial;
    }

    private String getLawyerRegCode() {
        // Option 1: environment variable
        String env = System.getenv("LAWYER_REG_CODE");
        if (env != null && !env.isBlank()) return env.trim();

        // Option 2: file-based secret
        try {
            File f = new File(System.getProperty("user.dir"), "web-data/lawyer-reg-code.txt");
            if (!f.exists()) return null;
            return Files.readString(f.toPath(), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return null;
        }
    }

    @GetMapping("/{username}/public-key")
    public Map<String, Object> getPub(@PathVariable("username") String username) {
        var u = userStore.get(username);
        if (u == null) return Map.of("ok", false, "error", "User not found");
        return Map.of("ok", true, "publicKeyB64", u.publicKeyB64(), "role", u.role());
    }

    @GetMapping("/{username}/key-bundle")
    public Map<String, Object> getKeyBundle(@PathVariable("username") String username) {
        var u = userStore.get(username);
        if (u == null) return Map.of("ok", false, "error", "User not found");
        if (u.encPrivB64() == null || u.saltB64() == null || u.ivB64() == null) {
            return Map.of("ok", false, "error", "No key bundle stored for user");
        }
        return Map.of(
                "ok", true,
                "username", u.username(),
                "publicKeyB64", u.publicKeyB64(),
                "saltB64", u.saltB64(),
                "ivB64", u.ivB64(),
                "encPrivB64", u.encPrivB64()
        );
    }
}
