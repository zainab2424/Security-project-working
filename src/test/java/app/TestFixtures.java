package app;

import app.Protocol.Msg;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import web.api.ContractController;
import web.store.UserStore;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class TestFixtures {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static final byte[] SAMPLE_CONTRACT = """
            Secure Legal Contract Delivery System
            Contract fixture
            Clause 1: recipient must sign before release.
            """.getBytes(StandardCharsets.UTF_8);

    static final byte[] SAMPLE_CONTRACT_LARGE = createRepeatedPayload(256 * 1024, (byte) 'C');
    static final byte[] SAMPLE_CONTRACT_MEDIUM = createRepeatedPayload(64 * 1024, (byte) 'M');
    static final byte[] SAMPLE_CONTRACT_SMALL = createRepeatedPayload(4 * 1024, (byte) 'S');

    private TestFixtures() {}

    static UserIdentity fixedAliceLawyer() throws Exception {
        return new UserIdentity(
                "alice-lawyer",
                "LAWYER",
                CryptoUtils.bytesToPublicKey(Files.readAllBytes(Path.of("keys", "alice.pub"))),
                CryptoUtils.bytesToPrivateKey(Files.readAllBytes(Path.of("keys", "alice.priv")))
        );
    }

    static UserIdentity fixedBobClient() throws Exception {
        return new UserIdentity(
                "bob-client",
                "CLIENT",
                CryptoUtils.bytesToPublicKey(Files.readAllBytes(Path.of("keys", "bob.pub"))),
                CryptoUtils.bytesToPrivateKey(Files.readAllBytes(Path.of("keys", "bob.priv")))
        );
    }

    static UserIdentity generatedClient(String username) throws Exception {
        KeyPair kp = CryptoUtils.generateECKeyPair();
        return new UserIdentity(username, "CLIENT", kp.getPublic(), kp.getPrivate());
    }

    static void registerUsers(UserIdentity... users) throws Exception {
        UserStore store = new UserStore();
        for (UserIdentity user : users) {
            store.upsert(
                    user.username(),
                    user.role(),
                    user.publicKeyB64(),
                    Base64.getEncoder().encodeToString("salt-fixture".getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString("fixture-iv-123".getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString("encrypted-private-placeholder".getBytes(StandardCharsets.UTF_8))
            );

            Msg reg = new Msg();
            reg.type = "REGISTER";
            reg.from = user.username();
            reg.publicKeyB64 = user.publicKeyB64();

            Msg resp = TestEnvironmentSupport.bridge().send(reg);
            if (!"REGISTER_OK".equals(resp.type)) {
                throw new IllegalStateException("Failed to register socket user: " + resp.error);
            }
        }
    }

    static ProtectedContract protectForRecipient(byte[] plaintext, UserIdentity recipient, boolean includeBogus) throws Exception {
        SecretKey realFileKey = CryptoUtils.generateAesKey();
        CryptoUtils.AesGcmBlob realBlob = CryptoUtils.aesGcmEncrypt(realFileKey, plaintext);
        CryptoUtils.WrappedKey realWrap = CryptoUtils.wrapAesKeyForRecipient(recipient.publicKey(), realFileKey, new java.security.SecureRandom());

        String hashB64 = CryptoUtils.b64(CryptoUtils.sha256(plaintext));

        String bogusArtifactTag = null;
        String bogusIvB64 = null;
        String bogusCtB64 = null;
        String bogusHashB64 = null;
        String bogusEphPubB64 = null;
        String bogusWrapIvB64 = null;
        String bogusWrapCtB64 = null;

        if (includeBogus) {
            byte[] bogusPlaintext = ("BOGUS:" + new String(plaintext, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
            SecretKey bogusFileKey = CryptoUtils.generateAesKey();
            CryptoUtils.AesGcmBlob bogusBlob = CryptoUtils.aesGcmEncrypt(bogusFileKey, bogusPlaintext);
            CryptoUtils.WrappedKey bogusWrap = CryptoUtils.wrapAesKeyForRecipient(recipient.publicKey(), bogusFileKey, new java.security.SecureRandom());

            bogusArtifactTag = "BOGUS_CERTIFIED_ARTIFACT_V1";
            bogusIvB64 = bogusBlob.ivB64();
            bogusCtB64 = bogusBlob.ctB64();
            bogusHashB64 = CryptoUtils.b64(CryptoUtils.sha256(bogusPlaintext));
            bogusEphPubB64 = bogusWrap.ephPubB64();
            bogusWrapIvB64 = bogusWrap.wrapIvB64();
            bogusWrapCtB64 = bogusWrap.wrapCtB64();
        }

        return new ProtectedContract(
                plaintext,
                hashB64,
                realBlob.ivB64(),
                realBlob.ctB64(),
                realWrap.ephPubB64(),
                realWrap.wrapIvB64(),
                realWrap.wrapCtB64(),
                bogusArtifactTag,
                bogusIvB64,
                bogusCtB64,
                bogusHashB64,
                bogusEphPubB64,
                bogusWrapIvB64,
                bogusWrapCtB64
        );
    }

    static UploadResult uploadContract(ContractController controller,
                                       UserIdentity sender,
                                       UserIdentity recipient,
                                       byte[] plaintext,
                                       boolean includeBogus) throws Exception {
        ProtectedContract contract = protectForRecipient(plaintext, recipient, includeBogus);
        String timestampIso = Instant.now().toString();
        Map<String, String> body = new LinkedHashMap<>();
        body.put("from", sender.username());
        body.put("to", recipient.username());
        body.put("filename", "fixture-contract.txt");
        body.put("contractIvB64", contract.contractIvB64());
        body.put("contractCtB64", contract.contractCtB64());
        body.put("contractHashB64", contract.contractHashB64());
        body.put("ephPubB64", contract.ephPubB64());
        body.put("wrapIvB64", contract.wrapIvB64());
        body.put("wrapCtB64", contract.wrapCtB64());
        if (includeBogus) {
            body.put("bogusArtifactTag", contract.bogusArtifactTag());
            body.put("bogusContractIvB64", contract.bogusContractIvB64());
            body.put("bogusContractCtB64", contract.bogusContractCtB64());
            body.put("bogusContractHashB64", contract.bogusContractHashB64());
            body.put("bogusEphPubB64", contract.bogusEphPubB64());
            body.put("bogusWrapIvB64", contract.bogusWrapIvB64());
            body.put("bogusWrapCtB64", contract.bogusWrapCtB64());
        }
        body.put("timestampIso", timestampIso);
        body.put("signatureB64", sign(sender.privateKey(), "REQ|SEND|" + sender.username() + "|" + recipient.username() + "|-|" + timestampIso));

        Map<String, Object> resp = controller.sendContract(body);
        if (!Boolean.TRUE.equals(resp.get("ok"))) {
            throw new IllegalStateException("Upload failed: " + resp.get("error"));
        }
        return new UploadResult((String) resp.get("contractId"), contract);
    }

    static String sign(PrivateKey key, String payload) throws Exception {
        return CryptoUtils.b64(CryptoUtils.sign(key, CryptoUtils.utf8(payload)));
    }

    static String receiptPayload(String contractId, String contractHashB64, String timestampIso) {
        return "RECEIPT|" + contractId + "|" + contractHashB64 + "|" + timestampIso;
    }

    static String decryptProofPayload(String contractId, String witnessHashB64, String timestampIso) {
        return "DECRYPT_PROOF|" + contractId + "|" + witnessHashB64 + "|" + timestampIso;
    }

    static String signRequest(UserIdentity user, String requestType, String contractId, String timestampIso) throws Exception {
        String payload = switch (requestType) {
            case "GET" -> "REQ|GET|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "KEY" -> "REQ|KEY|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "RECEIPT" -> "REQ|RECEIPT|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "DECRYPT_PROOF" -> "REQ|DECRYPT_PROOF|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "OT_OFFER" -> "REQ|OT_OFFER|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "AUDIT" -> "REQ|AUDIT|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "AUDIT_GLOBAL" -> "REQ|AUDIT_GLOBAL|" + user.username() + "|-|" + contractId + "|" + timestampIso;
            case "SENT" -> "REQ|SENT|" + user.username() + "|-|-|" + timestampIso;
            case "INBOX" -> "REQ|INBOX|" + user.username() + "|-|-|" + timestampIso;
            default -> throw new IllegalArgumentException("Unknown request type " + requestType);
        };
        return sign(user.privateKey(), payload);
    }

    static byte[] decryptReleasedContract(Map<String, Object> releasedKey, Map<String, Object> contractData, PrivateKey recipientPrivateKey)
            throws Exception {
        CryptoUtils.WrappedKey wrappedKey = new CryptoUtils.WrappedKey(
                (String) releasedKey.get("ephPubB64"),
                (String) releasedKey.get("wrapIvB64"),
                (String) releasedKey.get("wrapCtB64")
        );
        SecretKey fileKey = CryptoUtils.unwrapAesKey(recipientPrivateKey, wrappedKey);
        return CryptoUtils.aesGcmDecrypt(
                fileKey,
                (String) contractData.get("contractIvB64"),
                (String) contractData.get("contractCtB64")
        );
    }

    static List<Map<String, Object>> readAuditLogItems() throws Exception {
        return MAPPER.readValue(
                Files.readString(Path.of("web-data", "audit-log.json"), StandardCharsets.UTF_8),
                new TypeReference<>() {}
        );
    }

    private static byte[] createRepeatedPayload(int size, byte fill) {
        byte[] data = new byte[size];
        java.util.Arrays.fill(data, fill);
        return data;
    }

    record UserIdentity(String username, String role, PublicKey publicKey, PrivateKey privateKey) {
        String publicKeyB64() {
            return CryptoUtils.b64(CryptoUtils.publicKeyToBytes(publicKey));
        }
    }

    record ProtectedContract(byte[] plaintext,
                             String contractHashB64,
                             String contractIvB64,
                             String contractCtB64,
                             String ephPubB64,
                             String wrapIvB64,
                             String wrapCtB64,
                             String bogusArtifactTag,
                             String bogusContractIvB64,
                             String bogusContractCtB64,
                             String bogusContractHashB64,
                             String bogusEphPubB64,
                             String bogusWrapIvB64,
                             String bogusWrapCtB64) {}

    record UploadResult(String contractId, ProtectedContract protectedContract) {}
}
