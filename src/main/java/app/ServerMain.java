package app;

import app.OtUtils.Offer;
import app.Protocol.Msg;
import app.Protocol.RegisteredUserKey;
import app.Protocol.StoredContract;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/*
 * ServerMain is the socket-based delivery server.
 * It stores registered user keys, protected contracts, OT-style state,
 * and audit records, and it enforces the receipt and key-release protocol.
 */
public class ServerMain {
    private static final int PORT = 5050;
    private static final String BOGUS_ARTIFACT_TAG = "BOGUS_CERTIFIED_ARTIFACT_V1";

    // Maps usernames to registered public keys.
    private static final Map<String, PublicKey> USER_PUBKEYS = new ConcurrentHashMap<>();

    // Maps contract ids to stored contract state.
    private static final Map<String, StoredContract> CONTRACTS = new ConcurrentHashMap<>();

    // Persistent audit log store.
    private static final AuditLogStore AUDIT = new AuditLogStore();

    private static final File CONTRACTS_FILE = new File("web-data/contracts-store.json");
    private static final File USER_KEYS_FILE = new File("web-data/server-user-keys.json");
    private static final File GATEWAY_SECRET_FILE = new File("web-data/gateway-secret.txt");
    private static final String GATEWAY_SECRET = loadGatewaySecret();
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] args) throws Exception {
        // Restore persisted state before accepting requests.
        loadRegisteredUserKeys();
        loadContracts();
        System.out.println("Server listening on port " + PORT);
        try (ServerSocket ss = new ServerSocket(PORT)) {
            while (true) {
                Socket s = ss.accept();
                new Thread(() -> {
                    try (s) {
                        handleClient(s);
                    } catch (Exception e) {
                        System.err.println("Client error: " + e.getMessage());
                    }
                }).start();
            }
        }
    }

    /* Loads the shared gateway secret used for trusted direct requests. */
    private static String loadGatewaySecret() {
        try {
            if (!GATEWAY_SECRET_FILE.exists()) return null;
            return Files.readString(GATEWAY_SECRET_FILE.toPath()).trim();
        } catch (Exception e) {
            return null;
        }
    }

    /* Checks whether an incoming direct request came from the trusted web gateway. */
    private static boolean isAuthorizedGateway(Msg req) {
        return GATEWAY_SECRET != null
                && req != null
                && req.gatewayToken != null
                && GATEWAY_SECRET.equals(req.gatewayToken);
    }

    /* Returns true if any bogus artifact fields are present in the request. */
    private static boolean hasBogusArtifact(Msg req) {
        return req.bogusArtifactTag != null || req.bogusContractIvB64 != null || req.bogusContractCtB64 != null
                || req.bogusContractHashB64 != null || req.bogusEphPubB64 != null
                || req.bogusWrapIvB64 != null || req.bogusWrapCtB64 != null;
    }

    /* Returns true if all bogus artifact fields are present. */
    private static boolean isCompleteBogusArtifact(Msg req) {
        return req.bogusArtifactTag != null && req.bogusContractIvB64 != null && req.bogusContractCtB64 != null
                && req.bogusContractHashB64 != null && req.bogusEphPubB64 != null
                && req.bogusWrapIvB64 != null && req.bogusWrapCtB64 != null;
    }

    /* Writes one audit event to the persistent audit log. */
    private static void recordAudit(String eventType, String actor, String contractId, String detail) {
        String timestampIso = CryptoUtils.nowIso();
        String line = timestampIso + " " + detail;
        AUDIT.append(timestampIso, contractId, eventType, actor, line);
    }

    /*
     * Handles one client connection.
     * Supports registration, trusted gateway direct requests, and the normal auth flow.
     */
    private static void handleClient(Socket s) throws IOException, GeneralSecurityException {
        // Read the first incoming message for routing.
        Msg first = NetUtils.readJson(s, Msg.class);

        // Handle public key registration
        if ("REGISTER".equals(first.type)) {
            PublicKey pk = CryptoUtils.bytesToPublicKey(CryptoUtils.b64d(first.publicKeyB64));
            USER_PUBKEYS.put(first.from, pk);
            persistRegisteredUserKeys();
            recordAudit("REGISTER", first.from, null, "REGISTER user=" + first.from);
            Msg resp = new Msg();
            resp.type = "REGISTER_OK";
            resp.ok = "true";
            NetUtils.sendJson(s, resp);
            return;
        }

        // Allow trusted gateway direct calls only if gateway token is valid
        switch (first.type) {
            case "UPLOAD_CONTRACT", "GET_CONTRACT", "SUBMIT_RECEIPT", "GET_RELEASED_KEY",
                    "GET_AUDIT", "GET_RECEIPT", "SUBMIT_DECRYPT_PROOF", "GET_DECRYPT_PROOF",
                    "GET_OT_OFFER", "SUBMIT_OT_SELECTION" -> {
                if (!isAuthorizedGateway(first)) {
                    sendErr(s, "Unauthorized gateway");
                    return;
                }

                switch (first.type) {
                    case "UPLOAD_CONTRACT" -> {
                        handleUpload(s, first.from, first);
                        return;
                    }
                    case "GET_CONTRACT" -> {
                        handleGetContract(s, first.from, first);
                        return;
                    }
                    case "SUBMIT_RECEIPT" -> {
                        handleReceipt(s, first.from, first);
                        return;
                    }
                    case "GET_RELEASED_KEY" -> {
                        handleReleasedKey(s, first.from, first);
                        return;
                    }
                    case "GET_AUDIT" -> {
                        handleAudit(s, first.from, first);
                        return;
                    }
                    case "GET_RECEIPT" -> {
                        handleGetReceipt(s, first.from, first);
                        return;
                    }
                    case "SUBMIT_DECRYPT_PROOF" -> {
                        handleDecryptProof(s, first.from, first);
                        return;
                    }
                    case "GET_DECRYPT_PROOF" -> {
                        handleGetDecryptProof(s, first.from, first);
                        return;
                    }
                    case "GET_OT_OFFER" -> {
                        handleGetOtOffer(s, first.from, first);
                        return;
                    }
                    case "SUBMIT_OT_SELECTION" -> {
                        handleOtSelection(s, first.from, first);
                        return;
                    }
                }
            }
        }

        // Otherwise fall back to original AUTH_START flow 
        if (!"AUTH_START".equals(first.type)) {
            Msg err = new Msg();
            err.type = "ERR";
            err.error = "Expected REGISTER, direct request, or AUTH_START";
            NetUtils.sendJson(s, err);
            return;
        }

        // Look up the public key for the claimed user.
        String user = first.from;
        PublicKey pk = USER_PUBKEYS.get(user);
        if (pk == null) {
            sendErr(s, "Unknown user");
            return;
        }

        // Issue a nonce challenge
        Msg challenge = new Msg();
        challenge.type = "AUTH_CHALLENGE";
        byte[] nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        challenge.nonceB64 = CryptoUtils.b64(nonce);
        NetUtils.sendJson(s, challenge);

        // Read the signed proof response
        Msg proof = NetUtils.readJson(s, Msg.class);
        if (!"AUTH_PROVE".equals(proof.type)) {
            Msg err = new Msg();
            err.type = "ERR";
            err.error = "Expected AUTH_PROVE";
            NetUtils.sendJson(s, err);
            return;
        }

        // Verify the signature over the nonce
        boolean ok = CryptoUtils.verify(pk, CryptoUtils.b64d(challenge.nonceB64), CryptoUtils.b64d(proof.signatureB64));
        if (!ok) {
            recordAudit("AUTH_FAIL", user, null, "AUTH_FAIL user=" + user);
            Msg err = new Msg();
            err.type = "AUTH_FAIL";
            err.error = "Signature verification failed";
            NetUtils.sendJson(s, err);
            return;
        }

        // Authentication succeeded
        recordAudit("AUTH_OK", user, null, "AUTH_OK user=" + user);
        Msg authOk = new Msg();
        authOk.type = "AUTH_OK";
        authOk.ok = "true";
        NetUtils.sendJson(s, authOk);

        // Read and handle one follow-up request.
        Msg req = NetUtils.readJson(s, Msg.class);

        switch (req.type) {
            case "UPLOAD_CONTRACT" -> handleUpload(s, user, req);
            case "GET_CONTRACT" -> handleGetContract(s, user, req);
            case "SUBMIT_RECEIPT" -> handleReceipt(s, user, req);
            case "GET_RELEASED_KEY" -> handleReleasedKey(s, user, req);
            case "GET_AUDIT" -> handleAudit(s, user, req);
            case "GET_RECEIPT" -> handleGetReceipt(s, user, req);
            case "SUBMIT_DECRYPT_PROOF" -> handleDecryptProof(s, user, req);
            case "GET_DECRYPT_PROOF" -> handleGetDecryptProof(s, user, req);
            case "GET_OT_OFFER" -> handleGetOtOffer(s, user, req);
            case "SUBMIT_OT_SELECTION" -> handleOtSelection(s, user, req);
            default -> {
                Msg err = new Msg();
                err.type = "ERR";
                err.error = "Unknown request type";
                NetUtils.sendJson(s, err);
            }
        }
    }

    /* Stores a newly uploaded contract and prepares OT-style values when needed. */
    private static void handleUpload(Socket s, String sender, Msg req) throws IOException {
        boolean hasBogusArtifact = hasBogusArtifact(req);
        if (hasBogusArtifact && !isCompleteBogusArtifact(req)) {
            sendErr(s, "Incomplete bogus artifact");
            return;
        }
        if (hasBogusArtifact) {
            if (!BOGUS_ARTIFACT_TAG.equals(req.bogusArtifactTag)) {
                sendErr(s, "Invalid bogus artifact tag");
                return;
            }
            if (Objects.equals(req.contractHashB64, req.bogusContractHashB64)) {
                sendErr(s, "Bogus artifact must differ from real artifact");
                return;
            }
            if (Objects.equals(req.contractCtB64, req.bogusContractCtB64)) {
                sendErr(s, "Bogus ciphertext must differ from real ciphertext");
                return;
            }
            if (Objects.equals(req.wrapCtB64, req.bogusWrapCtB64)) {
                sendErr(s, "Bogus wrapped key must differ from real wrapped key");
                return;
            }
        }

        String contractId = UUID.randomUUID().toString();

        StoredContract c = new StoredContract();
        c.contractId = contractId;
        c.sender = sender;
        c.recipient = req.to;
        c.filename = req.filename;
        c.contractIvB64 = req.contractIvB64;
        c.contractCtB64 = req.contractCtB64;
        c.contractHashB64 = req.contractHashB64;
        c.bogusArtifactTag = req.bogusArtifactTag;
        c.bogusContractIvB64 = req.bogusContractIvB64;
        c.bogusContractCtB64 = req.bogusContractCtB64;
        c.bogusContractHashB64 = req.bogusContractHashB64;
        c.ephPubB64 = req.ephPubB64;
        c.wrapIvB64 = req.wrapIvB64;
        c.wrapCtB64 = req.wrapCtB64;
        c.bogusEphPubB64 = req.bogusEphPubB64;
        c.bogusWrapIvB64 = req.bogusWrapIvB64;
        c.bogusWrapCtB64 = req.bogusWrapCtB64;
        
         // Prepare OT-style offer values when bogus artifacts are present.
        if (hasBogusArtifact) {
            try {
                Offer otOffer = OtUtils.buildOffer(
                        contractId,
                        c.contractHashB64,
                        c.bogusContractHashB64,
                        c.wrapCtB64,
                        c.bogusWrapCtB64
                );
                c.otProtocolTag = otOffer.protocolTag();
                c.otTransferId = otOffer.transferId();
                c.otRealCommitmentB64 = otOffer.realCommitmentB64();
                c.otBogusCommitmentB64 = otOffer.bogusCommitmentB64();
            } catch (GeneralSecurityException e) {
                sendErr(s, "Failed to prepare OT offer");
                return;
            }
        }
        c.receiptReceived = false;

        CONTRACTS.put(contractId, c);
        persistContracts();
        recordAudit("UPLOAD", sender, contractId, "UPLOAD contractId=" + contractId + " from=" + sender + " to=" + req.to);

        Msg resp = new Msg();
        resp.type = "UPLOAD_OK";
        resp.contractId = contractId;
        resp.ok = "true";
        NetUtils.sendJson(s, resp);
    }

    /* Returns encrypted contract data to the intended recipient. */
    private static void handleGetContract(Socket s, String user, Msg req) throws IOException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can fetch contract");
            return;
        }

        Msg resp = new Msg();
        resp.type = "CONTRACT_DATA";
        resp.contractId = c.contractId;
        resp.from = c.sender;
        resp.to = c.recipient;
        resp.filename = c.filename;
        resp.contractIvB64 = c.contractIvB64;
        resp.contractCtB64 = c.contractCtB64;
        resp.contractHashB64 = c.contractHashB64;
        resp.receiptReceived = c.receiptReceived;
        resp.decryptProofReceived = c.decryptProofReceived;
        resp.receiptTimestampIso = c.receiptTimestampIso;
        resp.decryptProofTimestampIso = c.decryptProofTimestampIso;
        resp.bogusArtifactTag = c.bogusArtifactTag;
        resp.bogusContractIvB64 = c.bogusContractIvB64;
        resp.bogusContractCtB64 = c.bogusContractCtB64;
        resp.bogusContractHashB64 = c.bogusContractHashB64;
        resp.ok = "true";

        recordAudit("FETCH_CONTRACT", user, c.contractId, "FETCH_CONTRACT contractId=" + c.contractId + " by=" + user);
        NetUtils.sendJson(s, resp);
    }

     /* Verifies and records a signed receipt from the recipient. */
    private static void handleReceipt(Socket s, String user, Msg req) throws IOException, GeneralSecurityException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can submit receipt");
            return;
        }
        if (c.receiptReceived) {
            sendErr(s, "Receipt already recorded");
            return;
        }

        String payload = "RECEIPT|" + c.contractId + "|" + c.contractHashB64 + "|" + req.timestampIso;
        PublicKey recipientPk = USER_PUBKEYS.get(user);
        if (recipientPk == null) {
            sendErr(s, "Unknown user (not registered on delivery server). Restart ServerMain and re-register.");
            return;
        }

        boolean ok = CryptoUtils.verify(recipientPk, CryptoUtils.utf8(payload), CryptoUtils.b64d(req.signatureB64));
        if (!ok) {
            sendErr(s, "Invalid receipt signature");
            return;
        }

        c.receiptReceived = true;
        c.receiptSigB64 = req.signatureB64;
        c.receiptTimestampIso = req.timestampIso;
        persistContracts();

        recordAudit("RECEIPT_OK", user, c.contractId, "RECEIPT_OK contractId=" + c.contractId + " by=" + user + " ts=" + req.timestampIso);

        Msg resp = new Msg();
        resp.type = "RECEIPT_OK";
        resp.ok = "true";
        NetUtils.sendJson(s, resp);
    }

    /* Returns OT-style offer data after receipt has been recorded. */
    private static void handleGetOtOffer(Socket s, String user, Msg req) throws IOException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can fetch OT offer");
            return;
        }
        if (!c.receiptReceived) {
            sendErr(s, "Receipt not received yet");
            return;
        }
        if (c.otTransferId == null) {
            sendErr(s, "OT not enabled for this contract");
            return;
        }

        Msg resp = new Msg();
        resp.type = "OT_OFFER_DATA";
        resp.ok = "true";
        resp.contractId = c.contractId;
        resp.otProtocolTag = c.otProtocolTag;
        resp.otTransferId = c.otTransferId;
        resp.otRealCommitmentB64 = c.otRealCommitmentB64;
        resp.otBogusCommitmentB64 = c.otBogusCommitmentB64;
        if (c.otSelection != null) resp.otSelection = c.otSelection;

        recordAudit("OT_OFFER_FETCH", user, c.contractId, "OT_OFFER_FETCH contractId=" + c.contractId + " by=" + user);
        NetUtils.sendJson(s, resp);
    }

    /* Verifies and stores the recipient's OT-style selection. */
    private static void handleOtSelection(Socket s, String user, Msg req) throws IOException, GeneralSecurityException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can submit OT selection");
            return;
        }
        if (!c.receiptReceived) {
            sendErr(s, "Receipt not received yet");
            return;
        }
        if (c.otTransferId == null) {
            sendErr(s, "OT not enabled for this contract");
            return;
        }
        if (c.otSelection != null) {
            sendErr(s, "OT selection already recorded");
            return;
        }
        if (!Objects.equals(req.otProtocolTag, c.otProtocolTag)) {
            sendErr(s, "Invalid OT protocol tag");
            return;
        }
        if (!Objects.equals(req.otTransferId, c.otTransferId)) {
            sendErr(s, "Invalid OT transfer id");
            return;
        }

        String choice;
        try {
            choice = OtUtils.normalizeChoice(req.otSelection);
        } catch (IllegalArgumentException e) {
            sendErr(s, e.getMessage());
            return;
        }

        PublicKey recipientPk = USER_PUBKEYS.get(user);
        if (recipientPk == null) {
            sendErr(s, "Unknown user (not registered on delivery server). Restart ServerMain and re-register.");
            return;
        }

        String payload = OtUtils.selectionPayload(c.contractId, c.otTransferId, choice, req.timestampIso);
        boolean ok = CryptoUtils.verify(recipientPk, CryptoUtils.utf8(payload), CryptoUtils.b64d(req.signatureB64));
        if (!ok) {
            sendErr(s, "Invalid OT selection signature");
            return;
        }

        c.otSelection = choice;
        c.otSelectionSigB64 = req.signatureB64;
        c.otSelectionTimestampIso = req.timestampIso;
        persistContracts();

        recordAudit("OT_SELECTION_OK", user, c.contractId, "OT_SELECTION_OK contractId=" + c.contractId + " by=" + user + " choice=" + choice);

        Msg resp = new Msg();
        resp.type = "OT_SELECTION_OK";
        resp.ok = "true";
        resp.otSelection = choice;
        NetUtils.sendJson(s, resp);
    }

    /* Releases the wrapped key only after the required protocol conditions are met. */
    private static void handleReleasedKey(Socket s, String user, Msg req) throws IOException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can request key");
            return;
        }
        if (!c.receiptReceived) {
            sendErr(s, "Receipt not received yet - key not released");
            return;
        }
        if (c.otTransferId != null && c.otSelection == null) {
            sendErr(s, "OT selection not completed yet");
            return;
        }

        Msg resp = new Msg();
        resp.type = "RELEASED_KEY";
        resp.contractId = c.contractId;

        // Return the selected wrapped key path.
        if (OtUtils.CHOICE_BOGUS.equals(c.otSelection)) {
            resp.ephPubB64 = c.bogusEphPubB64;
            resp.wrapIvB64 = c.bogusWrapIvB64;
            resp.wrapCtB64 = c.bogusWrapCtB64;
        } else {
            resp.ephPubB64 = c.ephPubB64;
            resp.wrapIvB64 = c.wrapIvB64;
            resp.wrapCtB64 = c.wrapCtB64;
        }
        resp.bogusArtifactTag = c.bogusArtifactTag;
        resp.bogusEphPubB64 = c.bogusEphPubB64;
        resp.bogusWrapIvB64 = c.bogusWrapIvB64;
        resp.bogusWrapCtB64 = c.bogusWrapCtB64;
        resp.otProtocolTag = c.otProtocolTag;
        resp.otTransferId = c.otTransferId;
        resp.otSelection = c.otSelection;
        resp.ok = "true";

        recordAudit("KEY_RELEASED", user, c.contractId, "KEY_RELEASED contractId=" + c.contractId + " to=" + user);
        NetUtils.sendJson(s, resp);
    }

     /* Verifies and records recipient decryption proof after successful local decryption. */
    private static void handleDecryptProof(Socket s, String user, Msg req)
            throws IOException, GeneralSecurityException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }
        if (!user.equals(c.recipient)) {
            sendErr(s, "Only recipient can submit decrypt proof");
            return;
        }
        if (!c.receiptReceived) {
            sendErr(s, "Receipt not received yet");
            return;
        }
        if (c.decryptProofReceived) {
            sendErr(s, "Decrypt proof already recorded");
            return;
        }

        // The witness hash must match the stored contract hash.
        if (!Objects.equals(req.contractHashB64, c.contractHashB64)) {
            sendErr(s, "Decrypt witness hash does not match stored contract hash");
            return;
        }

        String payload = "DECRYPT_PROOF|" + c.contractId + "|" + req.contractHashB64 + "|" + req.timestampIso;

        PublicKey recipientPk = USER_PUBKEYS.get(user);
        if (recipientPk == null) {
            sendErr(s, "Unknown user (not registered on delivery server). Restart ServerMain and re-register.");
            return;
        }

        boolean ok = CryptoUtils.verify(
                recipientPk,
                CryptoUtils.utf8(payload),
                CryptoUtils.b64d(req.signatureB64)
        );
        if (!ok) {
            sendErr(s, "Invalid decrypt proof signature");
            return;
        }

        c.decryptProofReceived = true;
        c.decryptProofSigB64 = req.signatureB64;
        c.decryptProofTimestampIso = req.timestampIso;
        c.decryptWitnessHashB64 = req.contractHashB64;
        persistContracts();

        recordAudit("DECRYPT_PROOF_OK", user, c.contractId, "DECRYPT_PROOF_OK contractId=" + c.contractId + " by=" + user + " ts=" + req.timestampIso);

        Msg resp = new Msg();
        resp.type = "DECRYPT_PROOF_OK";
        resp.ok = "true";
        NetUtils.sendJson(s, resp);
    }

    /* Returns recorded decrypt proof data to the original sender. */
    private static void handleGetDecryptProof(Socket s, String user, Msg req) throws IOException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }

        if (!user.equals(c.sender)) {
            sendErr(s, "Only sender can fetch decrypt proof");
            return;
        }

        if (!c.decryptProofReceived) {
            sendErr(s, "Decrypt proof not received yet");
            return;
        }

        Msg resp = new Msg();
        resp.type = "DECRYPT_PROOF_DATA";
        resp.ok = "true";
        resp.contractId = c.contractId;
        resp.contractHashB64 = c.decryptWitnessHashB64;
        resp.from = c.recipient;
        resp.to = c.sender;
        resp.signatureB64 = c.decryptProofSigB64;
        resp.timestampIso = c.decryptProofTimestampIso;

        recordAudit("DECRYPT_PROOF_FETCH", user, c.contractId, "DECRYPT_PROOF_FETCH contractId=" + c.contractId + " by=" + user);
        NetUtils.sendJson(s, resp);
    }

    /* Returns audit lines either globally or for one contract. */
    private static void handleAudit(Socket s, String user, Msg req) throws IOException {
        Msg resp = new Msg();
        resp.type = "AUDIT_DATA";
        List<String> lines = new ArrayList<>();
        if (req.contractId != null && !req.contractId.isBlank() && !"ALL".equals(req.contractId)) {
            for (AuditLogStore.AuditEntry entry : AUDIT.byContractDescending(req.contractId)) lines.add(entry.line());
        } else {
            for (AuditLogStore.AuditEntry entry : AUDIT.allDescending()) lines.add(entry.line());
        }
        resp.ok = String.join(" | ", lines);
        NetUtils.sendJson(s, resp);
    }

    /* Sends a standard error response back to the client. */
    private static void sendErr(Socket s, String msg) throws IOException {
        Msg err = new Msg();
        err.type = "ERR";
        err.error = msg;
        NetUtils.sendJson(s, err);
    }

    /* Restores registered public keys from disk on server startup. */
    private static void loadRegisteredUserKeys() {
        try {
            if (!USER_KEYS_FILE.exists()) return;
            RegisteredUserKey[] arr = MAPPER.readValue(USER_KEYS_FILE, RegisteredUserKey[].class);
            for (var r : arr) {
                if (r != null && r.username != null && r.publicKeyB64 != null) {
                    PublicKey pk = CryptoUtils.bytesToPublicKey(CryptoUtils.b64d(r.publicKeyB64));
                    USER_PUBKEYS.put(r.username, pk);
                }
            }
            System.out.println("Loaded " + USER_PUBKEYS.size() + " registered user keys from disk.");
        } catch (Exception e) {
            System.err.println("Failed to load registered user keys: " + e.getMessage());
        }
    }

    /* Persists the registered public key map to disk. */
    private static synchronized void persistRegisteredUserKeys() {
        try {
            USER_KEYS_FILE.getParentFile().mkdirs();

            List<RegisteredUserKey> out = new ArrayList<>();
            for (var entry : USER_PUBKEYS.entrySet()) {
                RegisteredUserKey r = new RegisteredUserKey();
                r.username = entry.getKey();
                r.publicKeyB64 = CryptoUtils.b64(CryptoUtils.publicKeyToBytes(entry.getValue()));
                out.add(r);
            }

            MAPPER.writeValue(USER_KEYS_FILE, out.toArray(new RegisteredUserKey[0]));
        } catch (Exception e) {
            System.err.println("Failed to persist registered user keys: " + e.getMessage());
        }
    }

    /* Restores stored contracts from disk on server startup. */
    private static void loadContracts() {
        try {
            if (!CONTRACTS_FILE.exists()) return;
            StoredContract[] arr = MAPPER.readValue(CONTRACTS_FILE, StoredContract[].class);
            for (var c : arr) {
                if (c != null && c.contractId != null) CONTRACTS.put(c.contractId, c);
            }
            System.out.println("Loaded " + CONTRACTS.size() + " contracts from disk.");
        } catch (Exception e) {
            System.err.println("Failed to load contracts: " + e.getMessage());
        }
    }

    /* Persists the current contract map to disk. */
    private static synchronized void persistContracts() {
        try {
            CONTRACTS_FILE.getParentFile().mkdirs();
            MAPPER.writeValue(CONTRACTS_FILE, CONTRACTS.values().toArray(new StoredContract[0]));
        } catch (Exception e) {
            System.err.println("Failed to persist contracts: " + e.getMessage());
        }
    }

    /* Returns recorded receipt data to the original sender. */
    private static void handleGetReceipt(Socket s, String user, Msg req) throws IOException {
        StoredContract c = CONTRACTS.get(req.contractId);
        if (c == null) {
            sendErr(s, "No such contractId");
            return;
        }

        if (!user.equals(c.sender)) {
            sendErr(s, "Only sender can fetch receipt");
            return;
        }

        if (!c.receiptReceived) {
            sendErr(s, "Receipt not received yet");
            return;
        }

        Msg resp = new Msg();
        resp.type = "RECEIPT_DATA";
        resp.ok = "true";
        resp.contractId = c.contractId;
        resp.contractHashB64 = c.contractHashB64;
        resp.from = c.recipient;
        resp.to = c.sender;
        resp.signatureB64 = c.receiptSigB64;
        resp.timestampIso = c.receiptTimestampIso;

        recordAudit("RECEIPT_FETCH", user, c.contractId, "RECEIPT_FETCH contractId=" + c.contractId + " by=" + user);
        NetUtils.sendJson(s, resp);
    }
}
