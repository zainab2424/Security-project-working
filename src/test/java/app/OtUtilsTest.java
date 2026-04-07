package app;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

// Tests OT helper logic and payload generation.
class OtUtilsTest {
    @Test
    // Offer values should be tied to the contract and wrapped artifacts.
    void buildOfferBindsArtifactsToContract() throws Exception {
        var offer1 = OtUtils.buildOffer("c1", "realHash", "bogusHash", "realWrap", "bogusWrap");
        var offer2 = OtUtils.buildOffer("c2", "realHash", "bogusHash", "realWrap", "bogusWrap");

        assertNotEquals(offer1.transferId(), offer2.transferId());
        assertNotEquals(offer1.realCommitmentB64(), offer2.realCommitmentB64());
        assertNotEquals(offer1.bogusCommitmentB64(), offer2.bogusCommitmentB64());
        assertEquals(OtUtils.OT_PROTOCOL_TAG, offer1.protocolTag());
    }

    @Test
    // Commitment should change when the wrapped key changes.
    void commitmentChangesWhenWrappedKeyChanges() throws Exception {
        var offer = OtUtils.buildOffer("c1", "realHash", "bogusHash", "realWrap", "bogusWrap");
        String changedCommitment = OtUtils.commitmentForChoice(offer.transferId(), OtUtils.CHOICE_REAL, "realWrap2");

        assertNotEquals(offer.realCommitmentB64(), changedCommitment);
    }

    @Test
    // Selection payload should normalize valid choices and reject invalid ones.
    void selectionPayloadNormalizesChoiceAndRejectsInvalidChoice() {
        String payload = OtUtils.selectionPayload("c1", "tx1", "real", "2026-04-03T00:00:00Z");
        assertEquals("OT_SELECT|c1|tx1|REAL|2026-04-03T00:00:00Z", payload);
        assertThrows(IllegalArgumentException.class, () -> OtUtils.normalizeChoice("wrong"));
    }
}
