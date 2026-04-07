package web.api;

import org.springframework.web.bind.annotation.*;
import web.store.UserStore;

import java.util.Map;

// Handles authentication-related API requests.
@RestController
@RequestMapping("/api")
public class AuthController {

    // Logs in a user by checking whether the username exists.
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        // Re-read users.json each login to use the latest stored data.
        UserStore userStore = new UserStore();

        String username = body.get("username");
        var u = userStore.get(username);

        if (u == null) return Map.of("ok", false, "error", "Unknown user");
        return Map.of("ok", true, "role", u.role());
    }
}
