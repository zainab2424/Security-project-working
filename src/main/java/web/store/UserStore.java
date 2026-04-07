package web.store;

import java.io.File;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import app.CryptoUtils;
import web.util.Json;

// Stores user account and key bundle information.
public class UserStore {
    // Simple user record stored in users.json.
    public record User(String username, String role, String publicKeyB64,
                       String saltB64, String ivB64, String encPrivB64) {}

    private final File file = new File("web-data/users.json");
    private final Map<String, User> users = new ConcurrentHashMap<>();

    // Loads saved users from disk.
    public UserStore() {
        var loaded = Json.read(file, User[].class, new User[0]);
        for (var u : loaded) users.put(u.username(), u);
    }

    // Adds or updates a user entry and saves it.
    public synchronized void upsert(String username, String role, String publicKeyB64,
                                    String saltB64, String ivB64, String encPrivB64) {
        users.put(username, new User(username, role, publicKeyB64, saltB64, ivB64, encPrivB64));
        persist();
    }

    // Returns a user by username.
    public User get(String username) {
        return users.get(username);
    }

    // Returns the decoded public key for a user.
    public PublicKey getPublicKey(String username) {
        try {
            User u = users.get(username);
            if (u == null) return null;
            return CryptoUtils.bytesToPublicKey(CryptoUtils.b64d(u.publicKeyB64()));
        } catch (Exception e) {
            return null;
        }
    }

    // Returns all stored users.
    public Collection<User> all() { return users.values(); }

    // Saves users to disk.
    private void persist() {
        Json.write(file, users.values().toArray(new User[0]));
    }
}

