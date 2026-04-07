package app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/*
 * AuditLogStore manages persistent audit log storage for the application.
 * It supports appending new entries and retrieving logs in descending timestamp order.
 */

public class AuditLogStore {
    /* Represents one audit log entry. */
    public record AuditEntry(String timestampIso, String contractId, String eventType, String actor, String line) {}

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private final File file;
    private final List<AuditEntry> entries = new ArrayList<>();

    /* Uses the default audit log file location. */
    public AuditLogStore() {
        this(new File("web-data/audit-log.json"));
    }

    /* Uses a provided file location and loads any existing entries. */
    public AuditLogStore(File file) {
        this.file = file;
        load();
    }

    /* Adds a new audit entry and persists it to disk. */
    public synchronized void append(String timestampIso, String contractId, String eventType, String actor, String line) {
        entries.add(new AuditEntry(timestampIso, contractId, eventType, actor, line));
        persist();
    }

    /* Returns all audit entries sorted newest first. */
    public synchronized List<AuditEntry> allDescending() {
        return sortDescending(entries);
    }

    /* Returns audit entries for one contract, sorted newest first. */
    public synchronized List<AuditEntry> byContractDescending(String contractId) {
        List<AuditEntry> out = new ArrayList<>();
        for (AuditEntry entry : entries) {
            if (contractId != null && contractId.equals(entry.contractId())) out.add(entry);
        }
        return sortDescending(out);
    }

    /* Sorts a list of entries by timestamp in descending order. */
    private List<AuditEntry> sortDescending(List<AuditEntry> source) {
        List<AuditEntry> out = new ArrayList<>(source);
        out.sort(Comparator.comparing(AuditEntry::timestampIso, Comparator.nullsLast(Comparator.naturalOrder())).reversed());
        return out;
    }

    /* Loads existing audit entries from disk if the file exists. */
    private void load() {
        try {
            if (!file.exists()) return;
            AuditEntry[] loaded = MAPPER.readValue(file, AuditEntry[].class);
            for (AuditEntry entry : loaded) {
                if (entry != null) entries.add(entry);
            }
        } catch (Exception e) {
            System.err.println("Failed to load audit logs: " + e.getMessage());
        }
    }

    /* Writes the current audit entries to disk. */
    private void persist() {
        try {
            File parent = file.getParentFile();
            if (parent != null) parent.mkdirs();
            MAPPER.writeValue(file, entries.toArray(new AuditEntry[0]));
        } catch (Exception e) {
            System.err.println("Failed to persist audit logs: " + e.getMessage());
        }
    }
}
