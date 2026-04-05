package app;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import web.api.ContractController;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtocolPerformanceTest {
    private TestFixtures.UserIdentity sender;
    private TestFixtures.UserIdentity recipient;
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
        TestFixtures.registerUsers(sender, recipient);
        controller = new ContractController();
    }

    @Test
    void encryptionTime_reportedForRepresentativePayloads() throws Exception {
        long small = measureEncryption(TestFixtures.SAMPLE_CONTRACT_SMALL);
        long medium = measureEncryption(TestFixtures.SAMPLE_CONTRACT_MEDIUM);
        long large = measureEncryption(TestFixtures.SAMPLE_CONTRACT_LARGE);

        System.out.println("PERF encryptionMs small=" + small + " medium=" + medium + " large=" + large);
        assertTrue(small >= 0);
        assertTrue(medium >= 0);
        assertTrue(large >= 0);
        assertTrue(large < 5000);
    }

    @Test
    void decryptionTime_reportedAfterKeyRelease() throws Exception {
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT_MEDIUM);
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

        long started = System.nanoTime();
        byte[] decrypted = TestFixtures.decryptReleasedContract(releasedKey, contractData, recipient.privateKey());
        long elapsedMs = Duration.ofNanos(System.nanoTime() - started).toMillis();

        System.out.println("PERF decryptionMs medium=" + elapsedMs);
        assertArrayEquals(TestFixtures.SAMPLE_CONTRACT_MEDIUM, decrypted);
        assertTrue(elapsedMs < 5000);
    }

    @Test
    void happyPathLatency_reportedEndToEnd() throws Exception {
        long started = System.nanoTime();
        TestFixtures.UploadResult uploaded = completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT_SMALL);
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
        long elapsedMs = Duration.ofNanos(System.nanoTime() - started).toMillis();

        System.out.println("PERF happyPathMs small=" + elapsedMs);
        assertArrayEquals(TestFixtures.SAMPLE_CONTRACT_SMALL, decrypted);
        assertTrue(elapsedMs < 8000);
    }

    @Test
    void sequentialContracts_scalingReportForMultipleRuns() throws Exception {
        long started = System.nanoTime();
        for (int i = 0; i < 5; i++) {
            completeHappyPathUntilKeyRelease(TestFixtures.SAMPLE_CONTRACT_SMALL);
        }
        long elapsedMs = Duration.ofNanos(System.nanoTime() - started).toMillis();

        System.out.println("PERF sequentialFiveContractsMs=" + elapsedMs);
        assertTrue(elapsedMs < 15000);
    }

    private long measureEncryption(byte[] payload) throws Exception {
        long started = System.nanoTime();
        TestFixtures.protectForRecipient(payload, recipient, false);
        return Duration.ofNanos(System.nanoTime() - started).toMillis();
    }

    private TestFixtures.UploadResult completeHappyPathUntilKeyRelease(byte[] plaintext) throws Exception {
        TestFixtures.UploadResult uploaded = TestFixtures.uploadContract(controller, sender, recipient, plaintext, false);
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
}
