package web.api;

import org.springframework.web.bind.annotation.*;
import web.store.UserStore;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        // Re-read users.json every login (avoids stale instance issue)
        UserStore userStore = new UserStore();

        String username = body.get("username");
        var u = userStore.get(username);

        if (u == null) return Map.of("ok", false, "error", "Unknown user");
        return Map.of("ok", true, "role", u.role());
    }
}

