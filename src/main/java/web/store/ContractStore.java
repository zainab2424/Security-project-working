package web.store;

import java.io.File;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import web.util.Json;

// Stores basic contract index data for the web layer.
public class ContractStore {
    // Simple contract record used for indexing.
    public record ContractIndex(String contractId, String sender, String recipient, String filename) {}

    private final File file = new File("web-data/contracts.json");
    private final Map<String, ContractIndex> idx = new ConcurrentHashMap<>();

    // Loads saved contract index data from disk.
    public ContractStore() {
        var loaded = Json.read(file, ContractIndex[].class, new ContractIndex[0]);
        for (var c : loaded) idx.put(c.contractId(), c);
    }

    // Adds a new contract entry and saves it.
    public synchronized void add(String contractId, String sender, String recipient, String filename) {
        idx.put(contractId, new ContractIndex(contractId, sender, recipient, filename));
        persist();
    }

    // Returns contracts sent by the given user.
    public List<ContractIndex> sentBy(String user) {
        List<ContractIndex> out = new ArrayList<>();
        for (var c : idx.values()) if (c.sender().equals(user)) out.add(c);
        out.sort(Comparator.comparing(ContractIndex::contractId));
        return out;
    }

    // Returns contracts received by the given user.
    public List<ContractIndex> receivedBy(String user) {
        List<ContractIndex> out = new ArrayList<>();
        for (var c : idx.values()) if (c.recipient().equals(user)) out.add(c);
        out.sort(Comparator.comparing(ContractIndex::contractId));
        return out;
    }

    // Returns a contract entry by its ID.
    public ContractIndex get(String contractId) { return idx.get(contractId); }

    // Saves the current contract index to disk.
    private void persist() {
        Json.write(file, idx.values().toArray(new ContractIndex[0]));
    }
}
