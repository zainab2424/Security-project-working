package web.api;

import app.CryptoUtils;
import app.OtUtils;
import app.Protocol.Msg;
import org.springframework.web.bind.annotation.*;
import web.bridge.BridgeClient;
import web.store.ContractStore;
import web.store.UserStore;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

// Handles contract-related API requests.
@RestController
@RequestMapping("/api/contracts")
public class ContractController {
    // Tag used to identify bogus protected artifacts.
    private static final String BOGUS_ARTIFACT_TAG = "BOGUS_CERTIFIED_ARTIFACT_V1";

    // Bridge used to communicate with the socket server.
    private final BridgeClient bridge = new BridgeClient("127.0.0.1", 5050);
    private final ContractStore contractStore = new ContractStore();
    
    // ---------------- Replay Protection ----------------
    
    // Accept timestamps within +/- 120 seconds of server time
    private static final long MAX_SKEW_MS = Duration.ofSeconds(120).toMillis();

    // Keep seen signed payloads for 10 minutes (prevents reuse)
    private static final long SEEN_TTL_MS = Duration.ofMinutes(10).toMillis();

    // Stores previously seen signed payloads.
    private static final ConcurrentHashMap<String, Long> SEEN = new ConcurrentHashMap<>();

    // Counter used for periodic replay cache cleanup.
    private static final AtomicLong REPLAY_COUNTER = new AtomicLong(0);

    // Checks whether a request timestamp is still valid.
    private static boolean isFreshTimestamp(String timestampIso) {
        try {
            long ts = Instant.parse(timestampIso).toEpochMilli();
            long now = System.currentTimeMillis();
            return Math.abs(now - ts) <= MAX_SKEW_MS;
        } catch (Exception e) {
            return false;
        }
    }

    // Stores a signed payload if it has not already been used.
    private static boolean markIfNotReplayed(String signedPayload) {
        long now = System.currentTimeMillis();

        // periodic cleanup (cheap, avoids unbounded growth)
        long n = REPLAY_COUNTER.incrementAndGet();
        if (n % 100 == 0) {
            for (var it = SEEN.entrySet().iterator(); it.hasNext();) {
                var e = it.next();
                if (e.getValue() < now) it.remove();
            }
        }

        long expiry = now + SEEN_TTL_MS;
        return SEEN.putIfAbsent(signedPayload, expiry) == null;
    }

    /**
     * Extract timestampIso from a payload like:
     * REQ|TYPE|...|timestampIso
     */
    private static String extractTimestamp(String signedPayload) {
        String[] parts = signedPayload.split("\\|");
        if (parts.length < 2) return null;
        return parts[parts.length - 1];
    }

    // Reload UserStore each time so it always matches web-data/users.json
    private UserStore users() {
        return new UserStore();
    }

    // Checks whether any bogus artifact fields were provided.
    private static boolean hasAnyBogusField(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) return true;
        }
        return false;
    }

    // Checks whether all bogus artifact fields were provided.
    private static boolean hasAllBogusFields(String... values) {
        for (String value : values) {
            if (value == null || value.isBlank()) return false;
        }
        return true;
    }

    // Browser signs: "REQ|SEND|from|to|-|timestamp"
    // Browser signs: "REQ|GET|user|-|contractId|timestamp"
    // Browser signs: "REQ|KEY|user|-|contractId|timestamp"
    // Browser signs: "REQ|OT_OFFER|user|-|contractId|timestamp"
    // Browser signs: "REQ|SENT|user|-|-|timestamp"
    // Browser signs: "REQ|INBOX|user|-|-|timestamp"
    // Browser signs: "REQ|AUDIT|user|-|contractId|timestamp"
    // Browser signs: "REQ|AUDIT_GLOBAL|user|-|contractIdOrALL|timestamp"
    private boolean verifyRequestSig(String username, String signedPayload, String signatureB64) {
        try {
            PublicKey pk = users().getPublicKey(username);
            if (pk == null) return false;

            // 1) Verify signature first (prevents attackers filling replay cache)
            boolean sigOk = CryptoUtils.verify(pk, CryptoUtils.utf8(signedPayload), CryptoUtils.b64d(signatureB64));
            if (!sigOk) return false;

            // 2) Freshness check
            String ts = extractTimestamp(signedPayload);
            if (ts == null || !isFreshTimestamp(ts)) return false;

            // 3) One-time use check
            if (!markIfNotReplayed(signedPayload)) return false;

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Checks whether all bogus artifact fields were provided.
    private String ensureRegisteredOnSocketServer(String username) {
        try {
            PublicKey pk = users().getPublicKey(username);
            if (pk == null) return "Unknown user";

            Msg reg = new Msg();
            reg.type = "REGISTER";
            reg.from = username;
            reg.publicKeyB64 = CryptoUtils.b64(CryptoUtils.publicKeyToBytes(pk));

            Msg resp = bridge.send(reg);
            if (!"REGISTER_OK".equals(resp.type)) return resp.error != null ? resp.error : "Register failed";
            return null;
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    // Sends an encrypted contract to another user.
    @PostMapping("/send")
    public Map<String, Object> sendContract(@RequestBody Map<String, String> body) throws Exception {
        String from = body.get("from");
        String to = body.get("to");
        String filename = body.get("filename");

        String contractIvB64 = body.get("contractIvB64");
        String contractCtB64 = body.get("contractCtB64");
        String contractHashB64 = body.get("contractHashB64");
        String bogusArtifactTag = body.get("bogusArtifactTag");
        String bogusContractIvB64 = body.get("bogusContractIvB64");
        String bogusContractCtB64 = body.get("bogusContractCtB64");
        String bogusContractHashB64 = body.get("bogusContractHashB64");

        String ephPubB64 = body.get("ephPubB64");
        String wrapIvB64 = body.get("wrapIvB64");
        String wrapCtB64 = body.get("wrapCtB64");
        String bogusEphPubB64 = body.get("bogusEphPubB64");
        String bogusWrapIvB64 = body.get("bogusWrapIvB64");
        String bogusWrapCtB64 = body.get("bogusWrapCtB64");

        String ts = body.get("timestampIso");
        String sig = body.get("signatureB64");

        // Role check (read fresh from users.json)
        var u = users().get(from);
        if (u == null) return Map.of("ok", false, "error", "Unknown sender user");
        if (!"LAWYER".equals(u.role())) return Map.of("ok", false, "error", "Only LAWYER can send");

        // Verify signed request
        String payload = "REQ|SEND|" + from + "|" + to + "|-|" + ts;
        if (!verifyRequestSig(from, payload, sig)) return Map.of("ok", false, "error", "Bad signature");

        boolean hasAnyBogus = hasAnyBogusField(
                bogusArtifactTag, bogusContractIvB64, bogusContractCtB64, bogusContractHashB64,
                bogusEphPubB64, bogusWrapIvB64, bogusWrapCtB64
        );
        if (hasAnyBogus && !hasAllBogusFields(
                bogusArtifactTag, bogusContractIvB64, bogusContractCtB64, bogusContractHashB64,
                bogusEphPubB64, bogusWrapIvB64, bogusWrapCtB64
        )) {
            return Map.of("ok", false, "error", "Incomplete bogus artifact");
        }
        if (hasAnyBogus) {
            if (!BOGUS_ARTIFACT_TAG.equals(bogusArtifactTag)) {
                return Map.of("ok", false, "error", "Invalid bogus artifact tag");
            }
            if (contractHashB64 != null && contractHashB64.equals(bogusContractHashB64)) {
                return Map.of("ok", false, "error", "Bogus artifact must differ from real artifact");
            }
            if (contractCtB64 != null && contractCtB64.equals(bogusContractCtB64)) {
                return Map.of("ok", false, "error", "Bogus ciphertext must differ from real ciphertext");
            }
            if (wrapCtB64 != null && wrapCtB64.equals(bogusWrapCtB64)) {
                return Map.of("ok", false, "error", "Bogus wrapped key must differ from real wrapped key");
            }
        }

        // Forward to socket server
        Msg upload = new Msg();
        upload.type = "UPLOAD_CONTRACT";
        upload.from = from;
        upload.to = to;
        upload.filename = filename;

        upload.contractIvB64 = contractIvB64;
        upload.contractCtB64 = contractCtB64;
        upload.contractHashB64 = contractHashB64;
        upload.bogusArtifactTag = bogusArtifactTag;
        upload.bogusContractIvB64 = bogusContractIvB64;
        upload.bogusContractCtB64 = bogusContractCtB64;
        upload.bogusContractHashB64 = bogusContractHashB64;

        upload.ephPubB64 = ephPubB64;
        upload.wrapIvB64 = wrapIvB64;
        upload.wrapCtB64 = wrapCtB64;
        upload.bogusEphPubB64 = bogusEphPubB64;
        upload.bogusWrapIvB64 = bogusWrapIvB64;
        upload.bogusWrapCtB64 = bogusWrapCtB64;

        Msg resp = bridge.send(upload);
        if (!"UPLOAD_OK".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        contractStore.add(resp.contractId, from, to, filename);
        return Map.of("ok", true, "contractId", resp.contractId);
    }
    
    // Returns the signed receipt for a contract to the sender.
    @GetMapping("/{contractId}/receipt")
    public Map<String, Object> getReceipt(@PathVariable("contractId") String contractId,
                                        @RequestParam("username") String username,
                                        @RequestParam("timestampIso") String timestampIso,
                                        @RequestParam("signatureB64") String signatureB64) throws Exception {

        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");

        // Sender-only
        if (!idx.sender().equals(username)) return Map.of("ok", false, "error", "Only sender can fetch receipt");

        // Verify signed request
        String payload = "REQ|RECEIPT|" + username + "|-|" + contractId + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        // Ask delivery server
        Msg req = new Msg();
        req.type = "GET_RECEIPT";
        req.from = username;       // sender
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"RECEIPT_DATA".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        // Return a clean receipt bundle
        return Map.of(
                "ok", true,
                "contractId", resp.contractId,
                "recipient", resp.from, // signer
                "contractHashB64", resp.contractHashB64,
                "receiptTimestampIso", resp.timestampIso,
                "receiptSignatureB64", resp.signatureB64
        );
    }

    // Returns contracts sent by the given user.
    @GetMapping("/sent/{username}")
    public Map<String, Object> sent(@PathVariable("username") String username,
                                    @RequestParam("timestampIso") String timestampIso,
                                    @RequestParam("signatureB64") String signatureB64) {
        String payload = "REQ|SENT|" + username + "|-|-|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) {
            return Map.of("ok", false, "error", "Bad signature");
        }
        List<ContractStore.ContractIndex> items = contractStore.sentBy(username);
        return Map.of("ok", true, "items", items);
    }

    // Returns contracts received by the given user.
    @GetMapping("/inbox/{username}")
    public Map<String, Object> inbox(@PathVariable("username") String username,
                                     @RequestParam("timestampIso") String timestampIso,
                                     @RequestParam("signatureB64") String signatureB64) {
        String payload = "REQ|INBOX|" + username + "|-|-|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) {
            return Map.of("ok", false, "error", "Bad signature");
        }
        List<ContractStore.ContractIndex> items = contractStore.receivedBy(username);
        return Map.of("ok", true, "items", items);
    }

    // Returns encrypted contract data for the recipient.
    @GetMapping("/{contractId}")
    public Map<String, Object> getContract(@PathVariable("contractId") String contractId,
                                           @RequestParam("username") String username,
                                           @RequestParam("timestampIso") String timestampIso,
                                           @RequestParam("signatureB64") String signatureB64) throws Exception {
        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can fetch");

        String payload = "REQ|GET|" + username + "|-|" + contractId + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        Msg req = new Msg();
        req.type = "GET_CONTRACT";
        req.from = username;
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"CONTRACT_DATA".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("ok", true);
        out.put("from", resp.from);
        out.put("to", resp.to);
        out.put("filename", resp.filename);
        out.put("contractId", resp.contractId);
        out.put("contractIvB64", resp.contractIvB64);
        out.put("contractCtB64", resp.contractCtB64);
        out.put("contractHashB64", resp.contractHashB64);
        out.put("receiptReceived", resp.receiptReceived != null ? resp.receiptReceived : false);
        out.put("decryptProofReceived", resp.decryptProofReceived != null ? resp.decryptProofReceived : false);
        if (resp.receiptTimestampIso != null) out.put("receiptTimestampIso", resp.receiptTimestampIso);
        if (resp.decryptProofTimestampIso != null) out.put("decryptProofTimestampIso", resp.decryptProofTimestampIso);
        if (resp.bogusArtifactTag != null) out.put("bogusArtifactTag", resp.bogusArtifactTag);
        if (resp.bogusContractIvB64 != null) out.put("bogusContractIvB64", resp.bogusContractIvB64);
        if (resp.bogusContractCtB64 != null) out.put("bogusContractCtB64", resp.bogusContractCtB64);
        if (resp.bogusContractHashB64 != null) out.put("bogusContractHashB64", resp.bogusContractHashB64);
        return out;
    }

    // Returns the decrypt proof for a contract to the sender.
    @GetMapping("/{contractId}/decrypt-proof")
    public Map<String, Object> getDecryptProof(@PathVariable("contractId") String contractId,
                                            @RequestParam("username") String username,
                                            @RequestParam("timestampIso") String ts,
                                            @RequestParam("signatureB64") String reqSigB64) throws Exception {

        String signedPayload = "REQ|DECRYPT_PROOF|" + username + "|-|" + contractId + "|" + ts;
        if (!verifyRequestSig(username, signedPayload, reqSigB64)) {
            return Map.of("ok", false, "error", "Invalid request signature / replay / stale timestamp");
        }

        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.sender().equals(username)) return Map.of("ok", false, "error", "Only sender can fetch decrypt proof");

        String regErr = ensureRegisteredOnSocketServer(username);
        if (regErr != null) return Map.of("ok", false, "error", regErr);

        Msg req = new Msg();
        req.type = "GET_DECRYPT_PROOF";
        req.from = username;
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"DECRYPT_PROOF_DATA".equals(resp.type)) {
            return Map.of("ok", false, "error", resp.error);
        }

        return Map.of(
            "ok", true,
            "contractId", resp.contractId,
            "contractHashB64", resp.contractHashB64,
            "recipient", resp.from,
            "decryptProofSignatureB64", resp.signatureB64,
            "decryptProofTimestampIso", resp.timestampIso
        );
    }

    // Returns the OT offer for the recipient.
    @GetMapping("/{contractId}/ot-offer")
    public Map<String, Object> getOtOffer(@PathVariable("contractId") String contractId,
                                          @RequestParam("username") String username,
                                          @RequestParam("timestampIso") String timestampIso,
                                          @RequestParam("signatureB64") String signatureB64) throws Exception {
        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can fetch OT offer");

        String payload = "REQ|OT_OFFER|" + username + "|-|" + contractId + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        Msg req = new Msg();
        req.type = "GET_OT_OFFER";
        req.from = username;
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"OT_OFFER_DATA".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("ok", true);
        out.put("contractId", resp.contractId);
        out.put("otProtocolTag", resp.otProtocolTag);
        out.put("otTransferId", resp.otTransferId);
        out.put("otRealCommitmentB64", resp.otRealCommitmentB64);
        out.put("otBogusCommitmentB64", resp.otBogusCommitmentB64);
        if (resp.otSelection != null) out.put("otSelection", resp.otSelection);
        return out;
    }

    // Submits a signed receipt for a contract.
    @PostMapping("/{contractId}/receipt")
    public Map<String, Object> receipt(@PathVariable("contractId") String contractId,
                                       @RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String ts = body.get("timestampIso");
        String receiptSigB64 = body.get("receiptSignatureB64");

        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can receipt");

        String regErr = ensureRegisteredOnSocketServer(username);
        if (regErr != null) return Map.of("ok", false, "error", regErr);

        Msg req = new Msg();
        req.type = "SUBMIT_RECEIPT";
        req.from = username;
        req.contractId = contractId;
        req.timestampIso = ts;
        req.signatureB64 = receiptSigB64;

        Msg resp = bridge.send(req);
        if (!"RECEIPT_OK".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        return Map.of("ok", true);
    }

    // Submits decrypt proof after successful decryption.
    @PostMapping("/{contractId}/decrypt-proof")
    public Map<String, Object> decryptProof(@PathVariable("contractId") String contractId,
                                            @RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String witnessHashB64 = body.get("witnessHashB64");
        String ts = body.get("timestampIso");
        String decryptProofSigB64 = body.get("decryptProofSignatureB64");

        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can submit decrypt proof");

        String regErr = ensureRegisteredOnSocketServer(username);
        if (regErr != null) return Map.of("ok", false, "error", regErr);

        Msg req = new Msg();
        req.type = "SUBMIT_DECRYPT_PROOF";
        req.from = username;
        req.contractId = contractId;
        req.contractHashB64 = witnessHashB64;
        req.timestampIso = ts;
        req.signatureB64 = decryptProofSigB64;
        
        Msg resp = bridge.send(req);
        if (!"DECRYPT_PROOF_OK".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        return Map.of("ok", true);
    }

    // Submits the OT selection for a contract.
    @PostMapping("/{contractId}/ot-select")
    public Map<String, Object> submitOtSelection(@PathVariable("contractId") String contractId,
                                                 @RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String otProtocolTag = body.get("otProtocolTag");
        String otTransferId = body.get("otTransferId");
        String otSelection = body.get("otSelection");
        String timestampIso = body.get("timestampIso");
        String otSelectionSignatureB64 = body.get("otSelectionSignatureB64");

        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can submit OT selection");

        try {
            OtUtils.normalizeChoice(otSelection);
        } catch (IllegalArgumentException e) {
            return Map.of("ok", false, "error", e.getMessage());
        }

        String regErr = ensureRegisteredOnSocketServer(username);
        if (regErr != null) return Map.of("ok", false, "error", regErr);

        Msg req = new Msg();
        req.type = "SUBMIT_OT_SELECTION";
        req.from = username;
        req.contractId = contractId;
        req.otProtocolTag = otProtocolTag;
        req.otTransferId = otTransferId;
        req.otSelection = otSelection;
        req.timestampIso = timestampIso;
        req.signatureB64 = otSelectionSignatureB64;

        Msg resp = bridge.send(req);
        if (!"OT_SELECTION_OK".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        return Map.of("ok", true, "otSelection", resp.otSelection);
    }

    // Returns the released wrapped key for the recipient.
    @GetMapping("/{contractId}/released-key")
    public Map<String, Object> releasedKey(@PathVariable("contractId") String contractId,
                                           @RequestParam("username") String username,
                                           @RequestParam("timestampIso") String timestampIso,
                                           @RequestParam("signatureB64") String signatureB64) throws Exception {
        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.recipient().equals(username)) return Map.of("ok", false, "error", "Only recipient can get key");

        String payload = "REQ|KEY|" + username + "|-|" + contractId + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        Msg req = new Msg();
        req.type = "GET_RELEASED_KEY";
        req.from = username;
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"RELEASED_KEY".equals(resp.type)) return Map.of("ok", false, "error", resp.error);

        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("ok", true);
        out.put("ephPubB64", resp.ephPubB64);
        out.put("wrapIvB64", resp.wrapIvB64);
        out.put("wrapCtB64", resp.wrapCtB64);
        if (resp.bogusArtifactTag != null) out.put("bogusArtifactTag", resp.bogusArtifactTag);
        if (resp.bogusEphPubB64 != null) out.put("bogusEphPubB64", resp.bogusEphPubB64);
        if (resp.bogusWrapIvB64 != null) out.put("bogusWrapIvB64", resp.bogusWrapIvB64);
        if (resp.bogusWrapCtB64 != null) out.put("bogusWrapCtB64", resp.bogusWrapCtB64);
        if (resp.otProtocolTag != null) out.put("otProtocolTag", resp.otProtocolTag);
        if (resp.otTransferId != null) out.put("otTransferId", resp.otTransferId);
        if (resp.otSelection != null) out.put("otSelection", resp.otSelection);
        return out;
    }

    // Returns audit history, optionally filtered by contract.
    @GetMapping("/audit/history")
    public Map<String, Object> globalAudit(@RequestParam("username") String username,
                                           @RequestParam("timestampIso") String timestampIso,
                                           @RequestParam("signatureB64") String signatureB64,
                                           @RequestParam(value = "contractId", required = false) String contractId) throws Exception {
        String target = (contractId == null || contractId.isBlank()) ? "ALL" : contractId;
        String payload = "REQ|AUDIT_GLOBAL|" + username + "|-|" + target + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        if (contractId != null && !contractId.isBlank()) {
            var idx = contractStore.get(contractId);
            if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
            if (!idx.sender().equals(username) && !idx.recipient().equals(username)) {
                return Map.of("ok", false, "error", "Not allowed");
            }
        }

        Msg req = new Msg();
        req.type = "GET_AUDIT";
        req.from = username;
        req.contractId = target;

        Msg resp = bridge.send(req);
        if (!"AUDIT_DATA".equals(resp.type)) {
            return Map.of("ok", false, "error", resp.error);
        }

        List<String> lines = resp.ok == null || resp.ok.isBlank()
                ? java.util.Collections.emptyList()
                : java.util.Arrays.asList(resp.ok.split(" \\| "));

        return Map.of("ok", true, "lines", lines);
    }

    // Returns audit history for a specific contract.
    @GetMapping("/{contractId}/audit")
    public Map<String, Object> audit(@PathVariable("contractId") String contractId,
                                     @RequestParam("username") String username,
                                     @RequestParam("timestampIso") String timestampIso,
                                     @RequestParam("signatureB64") String signatureB64) throws Exception {
        var idx = contractStore.get(contractId);
        if (idx == null) return Map.of("ok", false, "error", "Unknown contractId");
        if (!idx.sender().equals(username) && !idx.recipient().equals(username)) return Map.of("ok", false, "error", "Not allowed");

        String payload = "REQ|AUDIT|" + username + "|-|" + contractId + "|" + timestampIso;
        if (!verifyRequestSig(username, payload, signatureB64)) return Map.of("ok", false, "error", "Bad signature");

        Msg req = new Msg();
        req.type = "GET_AUDIT";
        req.from = username;
        req.contractId = contractId;

        Msg resp = bridge.send(req);
        if (!"AUDIT_DATA".equals(resp.type)) {
            return Map.of("ok", false, "error", resp.error);
        }

        List<String> lines = resp.ok == null || resp.ok.isBlank()
                ? java.util.Collections.emptyList()
                : java.util.Arrays.asList(resp.ok.split(" \\| "));

        return Map.of("ok", true, "lines", lines);
    }
}
