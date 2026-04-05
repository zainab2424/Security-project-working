package app;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import web.api.ContractController;

import javax.crypto.AEADBadTagException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContractSecurityIntegrationTest {
    private TestFixtures.UserIdentity sender;
    private TestFixtures.UserIdentity recipient;
    private TestFixtures.UserIdentity otherRecipient;
    private ContractController controller;

    @BeforeAll
    static void beforeAll() throws Exception {
        TestEnvironmentSupport.beginSuite();
    }

    @AfterAll
    static void afterAll() throws Exception {
        TestEnvironmentSupport.endSuite();
    }

    @BeforeEach
    void setUp() throws Exception {
        TestEnvironmentSupport.resetForTest();
        sender = TestFixtures.fixedAliceLawyer();
        recipient = TestFixtures.fixedBobClient();
        otherRecipient = TestFixtures.generatedClient("mallory-client");
        TestFixtures.registerUsers(sender, recipient, otherRecipient);
        controller = new ContractController();
    }

    @Test
    void tamperedCiphertext_failsIntegrityAfterDecrypt() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease();
        String contractTs = Instant.now().toString();
        Map<String, Object> contractData = new LinkedHashMap<>(controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                contractTs,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), contractTs)
        ));
        String releaseTs = Instant.now().toString();
        Map<String, Object> releasedKey = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                releaseTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), releaseTs)
        );

        contractData.put("contractCtB64", mutateBase64((String) contractData.get("contractCtB64")));

        assertThrows(AEADBadTagException.class, () ->
                TestFixtures.decryptReleasedContract(releasedKey, contractData, recipient.privateKey()));
    }

    @Test
    void tamperedReceiptPayload_signatureVerificationFails() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String signedTs = Instant.now().toString();
        String signature = TestFixtures.sign(
                recipient.privateKey(),
                TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), signedTs)
        );

        Map<String, Object> resp = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", Instant.now().plusSeconds(5).toString(),
                "receiptSignatureB64", signature
        ));

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Invalid receipt signature", resp.get("error"));
    }

    @Test
    void forgedReceiptSignedBySender_isRejected() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();

        Map<String, Object> resp = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", ts,
                "receiptSignatureB64", TestFixtures.sign(
                        sender.privateKey(),
                        TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), ts)
                )
        ));

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Invalid receipt signature", resp.get("error"));
    }

    @Test
    void receiptForWrongContractHash_isRejected() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();
        Map<String, Object> resp = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", ts,
                "receiptSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.receiptPayload(uploaded.contractId(), "wrongHash", ts)
                )
        ));

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Invalid receipt signature", resp.get("error"));
    }

    @Test
    void validReceiptReplayedSecondTime_isRejectedAsDuplicate() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();
        String signature = TestFixtures.sign(
                recipient.privateKey(),
                TestFixtures.receiptPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), ts)
        );

        Map<String, Object> first = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", ts,
                "receiptSignatureB64", signature
        ));
        Map<String, Object> second = controller.receipt(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "timestampIso", ts,
                "receiptSignatureB64", signature
        ));

        assertEquals(Boolean.TRUE, first.get("ok"));
        assertEquals(Boolean.FALSE, second.get("ok"));
        assertEquals("Receipt already recorded", second.get("error"));
    }

    @Test
    void releasedKeyDeniedWithoutReceipt() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();

        Map<String, Object> resp = controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                ts,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), ts)
        );

        assertEquals(Boolean.FALSE, resp.get("ok"));
    }

    @Test
    void unauthorizedUserCannotFetchContract() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();

        Map<String, Object> resp = controller.getContract(
                uploaded.contractId(),
                sender.username(),
                ts,
                TestFixtures.signRequest(sender, "GET", uploaded.contractId(), ts)
        );

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Only recipient can fetch", resp.get("error"));
    }

    @Test
    void unauthorizedUserCannotFetchReleasedKey() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease();
        String ts = Instant.now().toString();

        Map<String, Object> resp = controller.releasedKey(
                uploaded.contractId(),
                sender.username(),
                ts,
                TestFixtures.signRequest(sender, "KEY", uploaded.contractId(), ts)
        );

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Only recipient can get key", resp.get("error"));
    }

    @Test
    void wrongPrivateKeyCannotDecryptReleasedContract() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease();
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

        assertThrows(AEADBadTagException.class, () ->
                TestFixtures.decryptReleasedContract(releasedKey, contractData, otherRecipient.privateKey()));
    }

    @Test
    void senderCannotForgeDecryptProofAsRecipient() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease();
        String ts = Instant.now().toString();
        Map<String, Object> resp = controller.decryptProof(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "witnessHashB64", uploaded.protectedContract().contractHashB64(),
                "timestampIso", ts,
                "decryptProofSignatureB64", TestFixtures.sign(
                        sender.privateKey(),
                        TestFixtures.decryptProofPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), ts)
                )
        ));

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Invalid decrypt proof signature", resp.get("error"));
    }

    @Test
    void auditLogContainsProtocolEventsForCorrectContract() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease();
        String releaseTs = Instant.now().toString();
        controller.releasedKey(
                uploaded.contractId(),
                recipient.username(),
                releaseTs,
                TestFixtures.signRequest(recipient, "KEY", uploaded.contractId(), releaseTs)
        );
        String proofTs = Instant.now().toString();
        controller.decryptProof(uploaded.contractId(), Map.of(
                "username", recipient.username(),
                "witnessHashB64", uploaded.protectedContract().contractHashB64(),
                "timestampIso", proofTs,
                "decryptProofSignatureB64", TestFixtures.sign(
                        recipient.privateKey(),
                        TestFixtures.decryptProofPayload(uploaded.contractId(), uploaded.protectedContract().contractHashB64(), proofTs)
                )
        ));

        String auditTs = Instant.now().toString();
        Map<String, Object> auditResp = controller.audit(
                uploaded.contractId(),
                sender.username(),
                auditTs,
                TestFixtures.signRequest(sender, "AUDIT", uploaded.contractId(), auditTs)
        );

        assertEquals(Boolean.TRUE, auditResp.get("ok"));
        @SuppressWarnings("unchecked")
        List<String> items = (List<String>) auditResp.get("lines");
        assertFalse(items.isEmpty());
        assertTrue(items.stream().allMatch(item -> item.contains(uploaded.contractId())));
        assertTrue(items.stream().anyMatch(item -> item.contains("UPLOAD contractId=" + uploaded.contractId())));
        assertTrue(items.stream().anyMatch(item -> item.contains("RECEIPT_OK contractId=" + uploaded.contractId())));
        assertTrue(items.stream().anyMatch(item -> item.contains("KEY_RELEASED contractId=" + uploaded.contractId())));
    }

    @Test
    void signedRequestReplayOnProtectedGet_isRejected() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String ts = Instant.now().toString();
        String sig = TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), ts);

        Map<String, Object> first = controller.getContract(uploaded.contractId(), recipient.username(), ts, sig);
        Map<String, Object> second = controller.getContract(uploaded.contractId(), recipient.username(), ts, sig);

        assertEquals(Boolean.TRUE, first.get("ok"));
        assertEquals(Boolean.FALSE, second.get("ok"));
        assertEquals("Bad signature", second.get("error"));
    }

    @Test
    void signedRequestWithStaleTimestamp_isRejected() throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, TestFixtures.SAMPLE_CONTRACT, false);
        String staleTs = Instant.now().minusSeconds(500).toString();

        Map<String, Object> resp = controller.getContract(
                uploaded.contractId(),
                recipient.username(),
                staleTs,
                TestFixtures.signRequest(recipient, "GET", uploaded.contractId(), staleTs)
        );

        assertEquals(Boolean.FALSE, resp.get("ok"));
        assertEquals("Bad signature", resp.get("error"));
    }

    private TestFixtures.UploadResult completeHappyPathUntilKeyRelease() throws Exception {
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

        return uploaded;
    }

    private static String mutateBase64(String input) {
        char replacement = input.charAt(input.length() - 1) == 'A' ? 'B' : 'A';
        return input.substring(0, input.length() - 1) + replacement;
    }
}
