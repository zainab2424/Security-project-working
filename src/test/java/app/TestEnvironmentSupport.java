package app;

import web.bridge.BridgeClient;
import web.api.ContractController;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

// Shared setup/reset helpers for integration and performance tests.
final class TestEnvironmentSupport {
    private static final Path WEB_DATA = Path.of("web-data");
    private static final List<String> FILES = List.of(
            "audit-log.json",
            "contracts-store.json",
            "contracts.json",
            "gateway-secret.txt",
            "lawyer-reg-code.txt",
            "server-user-keys.json",
            "users.json"
    );
    private static final String GATEWAY_SECRET = "test-gateway-secret";
    private static final String LAWYER_CODE = "LAWYER-TEST-CODE";

    private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);
    private static final AtomicBoolean SERVER_STARTED = new AtomicBoolean(false);
    private static final AtomicInteger ACTIVE_CLASSES = new AtomicInteger(0);
    private static final Map<String, byte[]> BACKUPS = new LinkedHashMap<>();

    private TestEnvironmentSupport() {}

    // Starts the shared test environment and server if needed.
    static synchronized void beginSuite() throws Exception {
        if (INITIALIZED.compareAndSet(false, true)) {
            backupFiles();
            resetPersistentFiles();
            startServerIfNeeded();
        }
        ACTIVE_CLASSES.incrementAndGet();
        resetRuntimeState();
    }

    // Restores original files after all test classes finish.
    static synchronized void endSuite() throws Exception {
        int remaining = ACTIVE_CLASSES.decrementAndGet();
        if (remaining <= 0 && INITIALIZED.get()) {
            restoreFiles();
            INITIALIZED.set(false);
        }
    }

    // Resets files and in-memory state before each test.
    static void resetForTest() throws Exception {
        resetPersistentFiles();
        resetRuntimeState();
    }

    // Returns the test gateway secret used by the bridge.
    static String gatewaySecret() {
        return GATEWAY_SECRET;
    }

    static String lawyerCode() {  // Returns the lawyer registration code used in tests.
        return LAWYER_CODE;
    }

    static BridgeClient bridge() {  // Creates a bridge client pointed at the local test server.
        return new BridgeClient("127.0.0.1", 5050);
    }

    private static void backupFiles() throws IOException { // Saves copies of original web-data files before tests run.
        Files.createDirectories(WEB_DATA);
        BACKUPS.clear();
        for (String name : FILES) {
            Path path = WEB_DATA.resolve(name);
            BACKUPS.put(name, Files.exists(path) ? Files.readAllBytes(path) : null);
        }
    }

    private static void restoreFiles() throws IOException { // Restores original web-data files after tests finish.
        for (Map.Entry<String, byte[]> entry : BACKUPS.entrySet()) {
            Path path = WEB_DATA.resolve(entry.getKey());
            byte[] content = entry.getValue();
            if (content == null) {
                Files.deleteIfExists(path);
            } else {
                Files.write(path, content);
            }
        }
    }

    private static void resetPersistentFiles() throws IOException {  // Resets persistent test files to a clean state.
        Files.createDirectories(WEB_DATA);
        writeText("audit-log.json", "[]\n");
        writeText("contracts-store.json", "[]\n");
        writeText("contracts.json", "[]\n");
        writeText("server-user-keys.json", "[]\n");
        writeText("users.json", "[]\n");
        writeText("gateway-secret.txt", GATEWAY_SECRET + "\n");
        writeText("lawyer-reg-code.txt", LAWYER_CODE + "\n");
    }

    private static void writeText(String fileName, String content) throws IOException {  // Starts the socket server once for the full test suite.
        Files.writeString(WEB_DATA.resolve(fileName), content, StandardCharsets.UTF_8);
    }

    private static void startServerIfNeeded() throws Exception { // Starts the socket server once for the full test suite. 
        if (SERVER_STARTED.compareAndSet(false, true)) {
            Thread t = new Thread(() -> {
                try {
                    ServerMain.main(new String[0]);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, "test-server-main");
            t.setDaemon(true);
            t.start();
            waitForPort(5050, Duration.ofSeconds(10));
        }
    }

    private static void waitForPort(int port, Duration timeout) throws Exception { // Waits until the local server port is available.
        long deadline = System.nanoTime() + timeout.toNanos();
        Exception last = null;
        while (System.nanoTime() < deadline) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 250);
                return;
            } catch (Exception e) {
                last = e;
                Thread.sleep(100);
            }
        }
        throw new IllegalStateException("Timed out waiting for server port " + port, last);
    }

    private static void resetRuntimeState() throws Exception { // Waits until the local server port is available.
        clearMapField(ServerMain.class, "USER_PUBKEYS");
        clearMapField(ServerMain.class, "CONTRACTS");
        clearAuditLogStore();
        clearMapField(ContractController.class, "SEEN");
        AtomicLongHolder.reset(ContractController.class, "REPLAY_COUNTER");
    }

    private static void clearAuditLogStore() throws Exception { // Clears the in-memory audit log entries.
        Field auditField = ServerMain.class.getDeclaredField("AUDIT");
        auditField.setAccessible(true);
        AuditLogStore audit = (AuditLogStore) auditField.get(null);
        
        // Clear the internal entries list
        Field entriesField = AuditLogStore.class.getDeclaredField("entries");
        entriesField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> entries = (List<Object>) entriesField.get(audit);
        entries.clear();
    }

    private static void clearMapField(Class<?> owner, String fieldName) throws Exception {  // Clears a static map field using reflection.
        Field field = owner.getDeclaredField(fieldName);
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<Object, Object> map = (Map<Object, Object>) field.get(null);
        map.clear();
    }

    private static void clearStaticListField(Class<?> owner, String fieldName) throws Exception {
        Field field = owner.getDeclaredField(fieldName);
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> list = (List<Object>) field.get(null);
        list.clear();
    }

    private static final class AtomicLongHolder { // Resets a static AtomicLong field using reflection.
        private static void reset(Class<?> owner, String fieldName) throws Exception {
            Field field = owner.getDeclaredField(fieldName);
            field.setAccessible(true);
            java.util.concurrent.atomic.AtomicLong value =
                    (java.util.concurrent.atomic.AtomicLong) field.get(null);
            value.set(0L);
        }
    }
}
