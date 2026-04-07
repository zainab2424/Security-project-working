package app;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import web.api.ContractController;
import web.store.ContractStore;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class ProtocolFlowIntegrationTest { // Integration tests for the main protocol flow.
    private TestFixtures.UserIdentity sender;
    private TestFixtures.UserIdentity recipient;
    private ContractController controller;

    @BeforeAll
    static void beforeAll() throws Exception {  // Starts shared test environment once for this test class.
        TestEnvironmentSupport.beginSuite();
    }

    @AfterAll
    static void afterAll() throws Exception {
        TestEnvironmentSupport.endSuite();
    }

    @BeforeEach
    void setUp() throws Exception {  // Resets state and prepares test users before each run.
        TestEnvironmentSupport.resetForTest();
        sender = TestFixtures.fixedAliceLawyer();
        recipient = TestFixtures.fixedBobClient();
        TestFixtures.registerUsers(sender, recipient);
        controller = new ContractController();
    }

    @Test 
    void uploadContract_acceptsEncryptedPayloadAndPersistsContract() throws Exception {  // Upload should accept encrypted payload and store contract data.
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);

        assertNotNull(uploaded.contractId());
        assertNotEquals(CryptoUtils.b64(TestFixtures.SAMPLE_CONTRACT), uploaded.protectedContract().contractCtB64());

        String getTs = Instant.now().toString();
        Map<String, Object> contractData = controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                getTs,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), getTs)
        );

        assertEquals(Boolean.TRUE, contractData.get("ok"));
        assertEquals(uploaded.contractId(), contractData.get("contractId"));
        assertEquals(uploaded.protectedContract().contractCtB64(), contractData.get("contractCtB64"));
    }

    @Test  // Sending a contract should create both contract ID and metadata entry.
    void sendContract_createsContractIdAndMetadataIndex() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);

        String sentTs = Instant.now().toString();
        Map<String, Object> sent = controller.sent(sender.username(), sentTs, TestFixtures.signRequest(sender, "SENT", "", sentTs));
        String inboxTs = Instant.now().toString();
        Map<String, Object> inbox = controller.inbox(recipient.username(), inboxTs, TestFixtures.signRequest(recipient, "INBOX", "", inboxTs));

        @SuppressWarnings("unchecked")
        List<ContractStore.ContractIndex> sentItems = (List<ContractStore.ContractIndex>) sent.get("items");
        @SuppressWarnings("unchecked")
        List<ContractStore.ContractIndex> inboxItems = (List<ContractStore.ContractIndex>) inbox.get("items");

        assertEquals(1, sentItems.size());
        assertEquals(1, inboxItems.size());
        assertEquals(uploaded.contractId(), sentItems.get(0).contractId());
        assertEquals(uploaded.contractId(), inboxItems.get(0).contractId());
    }

    @Test // Recipient can fetch encrypted data before receipt, but not the released key.
    void recipientCanFetchEncryptedContractButNotReleasedKeyBeforeReceipt() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();

        Map<String, Object> contractData = controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                ts,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), ts)
        );
        String keyTs = Instant.now().toString();
        Map<String, Object> released = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                keyTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), keyTs)
        );

        assertEquals(Boolean.TRUE, contractData.get("ok"));
        assertEquals(Boolean.FALSE, released.get("ok"));
        assertTrue(String.valueOf(released.get("error")).contains("Receipt not received yet"));
    }

    @Test // A valid receipt should be accepted and retrievable by the sender.
    void validReceiptSubmission_isAcceptedAndStored() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String receiptTs = Instant.now().toString();

        Map<String, Object> receiptResp = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", receiptTs,
                "receiptSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), receiptTs)
                )
        ));

        assertEquals(Boolean.TRUE, receiptResp.get("ok"));

        String fetchTs = Instant.now().toString();
        Map<String, Object> senderReceipt = controller.getReceipt(
                uploaded.contractId(),
                sender.username(),
                fetchTs,
                TestFixtures.signRequest(sender, "RECEIPT", uploaded.contractId(), fetchTs)
        );

        assertEquals(Boolean.TRUE, senderReceipt.get("ok"));
        assertEquals(uploaded.protectedContract().contractHashB64(), senderReceipt.get("contractHashB64"));
        assertEquals(recipient.username(), senderReceipt.get("recipient"));
    }

    @Test // Released key should become available after valid receipt submission.
    void releasedKey_availableImmediatelyAfterValidReceipt() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String receiptTs = Instant.now().toString();
        controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", receiptTs,
                "receiptSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), receiptTs)
                )
        ));

        String releaseTs = Instant.now().toString();
        Map<String, Object> released = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                releaseTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), releaseTs)
        );

        assertEquals(Boolean.TRUE, released.get("ok"));
        assertNotNull(released.get("ephPubB64"));
        assertNotNull(released.get("wrapCtB64"));
    }

    @Test  // Recipient should be able to decrypt and match the stored hash.
    void recipientCanUnwrapKeyDecryptContractAndMatchStoredHash() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT);

        String contractTs = Instant.now().toString();
        Map<String, Object> contractData = controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                contractTs,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), contractTs)
        );
        String releaseTs = Instant.now().toString();
        Map<String, Object> releasedKey = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                releaseTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), releaseTs)
        );

        byte[] decrypted = TestFixtures.decryptReleasedContract(releasedKey, contractData, recipient.privateKey());

        assertArrayEquals(TestFixtures.SAMPLE_CONTRACT, decrypted);
        assertEquals(uploaded.protectedContract().contractHashB64(), CryptoUtils.b64(CryptoUtils.sha256(decrypted)));
    }

    @Test  // Valid decrypt proof should be accepted and retrievable by the sender.
    void validDecryptProof_isAcceptedAndSenderCanFetchIt() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT);

        String proofTs = Instant.now().toString();
        Map<String, Object> proofResp = controller.decryptProof(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "witnessHashB64", uploaded.protectedContract().contractHashB64(),
                "timestampIso", proofTs,
                "decryptProofSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.decryptProofPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), proofTs)
                )
        ));

        assertEquals(Boolean.TRUE, proofResp.get("ok"));

        String fetchTs = Instant.now().toString();
        Map<String, Object> fetched = controller.getDecryptProof(
                uploaded.contractId(),
                sender.username(),
                fetchTs,
                TestFixtures.signRequest(sender, "DECRYPT_PROOF", uploaded.contractId(), fetchTs)
        );

        assertEquals(Boolean.TRUE, fetched.get("ok"));
        assertEquals(recipient.username(), fetched.get("recipient"));
    }

    @Test  // Valid decrypt proof should be accepted and retrievable by the sender.
    void fullHappyPath_uploadReceiptReleaseDecryptProof_succeeds() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT);

        String contractTs = Instant.now().toString();
        Map<String, Object> contractData = controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                contractTs,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), contractTs)
        );
        String releaseTs = Instant.now().toString();
        Map<String, Object> releasedKey = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                releaseTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), releaseTs)
        );

        byte[] decrypted = TestFixtures.decryptReleasedContract(releasedKey, contractData, recipient.privateKey());
        assertArrayEquals(TestFixtures.SAMPLE_CONTRACT, decrypted);

        String proofTs = Instant.now().toString();
        Map<String, Object> proofResp = controller.decryptProof(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "witnessHashB64", CryptoUtils.b64(CryptoUtils.sha256(decrypted)),
                "timestampIso", proofTs,
                "decryptProofSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.decryptProofPayload(uploaded.contractId(), CryptoUtils.b64(CryptoUtils.sha256(decrypted)), proofTs)
                )
        ));
        assertEquals(Boolean.TRUE, proofResp.get("ok"));

        String auditTs = Instant.now().toString();
        Map<String, Object> audit = controller.audit(
                uploaded.contractId(),
                sender.username(),
                auditTs,
                TestFixtures.signRequest(sender, "AUDIT", uploaded.contractId(), auditTs)
        );
        assertEquals(Boolean.TRUE, audit.get("ok"));

        @SuppressWarnings("unchecked")
        List<String> lines = (List<String>) audit.get("lines");
        assertTrue(lines.stream().anyMatch(line -> line.contains("UPLOAD contractId=" + uploaded.contractId())));
        assertTrue(lines.stream().anyMatch(line -> line.contains("RECEIPT_OK contractId=" + uploaded.contractId())));
        assertTrue(lines.stream().anyMatch(line -> line.contains("KEY_RELEASED contractId=" + uploaded.contractId())));
        assertTrue(lines.stream().anyMatch(line -> line.contains("DECRYPT_PROOF_OK contractId=" + uploaded.contractId())));
    }

     // Runs the flow up to successful key release.
    private TestFixtures.UploadResult completeHappyPathUntilKeyRelease(byte[] plaintext) throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, plaintext, false);
        String receiptTs = Instant.now().toString();
        Map<String, Object> receiptResp = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", receiptTs,
                "receiptSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), receiptTs)
                )
        ));
        assertEquals(Boolean.TRUE, receiptResp.get("ok"));
        return uploaded;
    }
}
