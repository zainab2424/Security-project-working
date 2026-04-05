package web.store;

import java.io.File;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import web.util.Json;

public class ContractStore {
    public record ContractIndex(String contractId, String sender, String recipient, String filename) {}

    private final File file = new File("web-data/contracts.json");
    private final Map<String, ContractIndex> idx = new ConcurrentHashMap<>();

    public ContractStore() {
        var loaded = Json.read(file, ContractIndex[].class, new ContractIndex[0]);
        for (var c : loaded) idx.put(c.contractId(), c);
    }

    public synchronized void add(String contractId, String sender, String recipient, String filename) {
        idx.put(contractId, new ContractIndex(contractId, sender, recipient, filename));
        persist();
    }

    public List<ContractIndex> sentBy(String user) {
        List<ContractIndex> out = new ArrayList<>();
        for (var c : idx.values()) if (c.sender().equals(user)) out.add(c);
        out.sort(Comparator.comparing(ContractIndex::contractId));
        return out;
    }

    public List<ContractIndex> receivedBy(String user) {
        List<ContractIndex> out = new ArrayList<>();
        for (var c : idx.values()) if (c.recipient().equals(user)) out.add(c);
        out.sort(Comparator.comparing(ContractIndex::contractId));
        return out;
    }

    public ContractIndex get(String contractId) { return idx.get(contractId); }

    private void persist() {
        Json.write(file, idx.values().toArray(new ContractIndex[0]));
    }
}
