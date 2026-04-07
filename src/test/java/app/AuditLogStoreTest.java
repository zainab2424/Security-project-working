package app;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

// Tests audit log storage and ordering behavior.
class AuditLogStoreTest {
    @Test
    // Confirms entries are saved and returned newest first.
    void persistsAndReturnsNewestFirst() throws Exception {
        File dir = Files.createTempDirectory("audit-log-store-test").toFile();
        File file = new File(dir, "audit-log.json");

        AuditLogStore store = new AuditLogStore(file);
        store.append("2026-04-02T10:00:00Z", "c1", "UPLOAD", "alice", "2026-04-02T10:00:00Z UPLOAD contractId=c1 from=alice to=bob");
        store.append("2026-04-02T11:00:00Z", "c2", "RECEIPT_OK", "bob", "2026-04-02T11:00:00Z RECEIPT_OK contractId=c2 by=bob ts=2026-04-02T11:00:00Z");

        AuditLogStore reloaded = new AuditLogStore(file);
        List<AuditLogStore.AuditEntry> all = reloaded.allDescending();

        assertEquals(2, all.size());
        assertEquals("2026-04-02T11:00:00Z", all.get(0).timestampIso());
        assertEquals("c2", all.get(0).contractId());
        assertEquals("2026-04-02T10:00:00Z", all.get(1).timestampIso());
    }

    @Test
    // Confirms filtering by contract keeps descending order.
    void filtersByContractWithoutLosingOrder() throws Exception {
        File dir = Files.createTempDirectory("audit-log-store-filter-test").toFile();
        File file = new File(dir, "audit-log.json");

        AuditLogStore store = new AuditLogStore(file);
        store.append("2026-04-02T09:00:00Z", "c1", "UPLOAD", "alice", "2026-04-02T09:00:00Z UPLOAD contractId=c1 from=alice to=bob");
        store.append("2026-04-02T10:00:00Z", "c2", "UPLOAD", "alice", "2026-04-02T10:00:00Z UPLOAD contractId=c2 from=alice to=carol");
        store.append("2026-04-02T11:00:00Z", "c1", "KEY_RELEASED", "bob", "2026-04-02T11:00:00Z KEY_RELEASED contractId=c1 to=bob");

        List<AuditLogStore.AuditEntry> filtered = store.byContractDescending("c1");

        assertEquals(2, filtered.size());
        assertEquals("2026-04-02T11:00:00Z", filtered.get(0).timestampIso());
        assertEquals("2026-04-02T09:00:00Z", filtered.get(1).timestampIso());
    }
}
