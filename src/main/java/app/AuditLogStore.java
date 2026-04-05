package app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class AuditLogStore {
    public record AuditEntry(String timestampIso, String contractId, String eventType, String actor, String line) {}

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private final File file;
    private final List<AuditEntry> entries = new ArrayList<>();

    public AuditLogStore() {
        this(new File("web-data/audit-log.json"));
    }

    public AuditLogStore(File file) {
        this.file = file;
        load();
    }

    public synchronized void append(String timestampIso, String contractId, String eventType, String actor, String line) {
        entries.add(new AuditEntry(timestampIso, contractId, eventType, actor, line));
        persist();
    }

    public synchronized List<AuditEntry> allDescending() {
        return sortDescending(entries);
    }

    public synchronized List<AuditEntry> byContractDescending(String contractId) {
        List<AuditEntry> out = new ArrayList<>();
        for (AuditEntry entry : entries) {
            if (contractId != null && contractId.equals(entry.contractId())) out.add(entry);
        }
        return sortDescending(out);
    }

    private List<AuditEntry> sortDescending(List<AuditEntry> source) {
        List<AuditEntry> out = new ArrayList<>(source);
        out.sort(Comparator.comparing(AuditEntry::timestampIso, Comparator.nullsLast(Comparator.naturalOrder())).reversed());
        return out;
    }

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
