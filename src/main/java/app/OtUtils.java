package app;

import java.security.GeneralSecurityException;

/*
 * OtUtils contains helper methods for the OT-style transfer stage.
 * It builds transfer identifiers, commitments, and signed selection payloads.
 */
public final class OtUtils {
    public static final String OT_PROTOCOL_TAG = "OT_STYLE_TRANSFER_V1";
    public static final String CHOICE_REAL = "REAL";
    public static final String CHOICE_BOGUS = "BOGUS";

    private OtUtils() {}

    /* Represents the OT-style offer values stored for a contract. */
    public record Offer(String protocolTag, String transferId, String realCommitmentB64, String bogusCommitmentB64) {}

    /*
     * Builds an OT-style offer for the real and bogus wrapped key paths.
     */
    public static Offer buildOffer(String contractId,
                                   String realHashB64,
                                   String bogusHashB64,
                                   String realWrapCtB64,
                                   String bogusWrapCtB64) throws GeneralSecurityException {
        String transferId = digestB64("OT_TRANSFER|" + contractId + "|" + realHashB64 + "|" + bogusHashB64);
        String realCommitment = commitmentForChoice(transferId, CHOICE_REAL, realWrapCtB64);
        String bogusCommitment = commitmentForChoice(transferId, CHOICE_BOGUS, bogusWrapCtB64);
        return new Offer(OT_PROTOCOL_TAG, transferId, realCommitment, bogusCommitment);
    }

    /* Builds a commitment value for one OT choice branch. */
    public static String commitmentForChoice(String transferId, String choice, String wrapCtB64) throws GeneralSecurityException {
        String normalizedChoice = normalizeChoice(choice);
        return digestB64("OT_COMMIT|" + transferId + "|" + normalizedChoice + "|" + wrapCtB64);
    }

    /* Builds the signed payload string for the recipient's OT selection. */
    public static String selectionPayload(String contractId, String transferId, String choice, String timestampIso) {
        return "OT_SELECT|" + contractId + "|" + transferId + "|" + normalizeChoice(choice) + "|" + timestampIso;
    }

    /* Validates and normalizes the OT selection value. */
    public static String normalizeChoice(String choice) {
        if (choice == null) throw new IllegalArgumentException("OT choice required");
        String normalized = choice.trim().toUpperCase();
        if (!CHOICE_REAL.equals(normalized) && !CHOICE_BOGUS.equals(normalized)) {
            throw new IllegalArgumentException("Invalid OT choice");
        }
        return normalized;
    }

    /* Computes a Base64-encoded SHA-256 digest for a string value. */
    private static String digestB64(String value) throws GeneralSecurityException {
        return CryptoUtils.b64(CryptoUtils.sha256(CryptoUtils.utf8(value)));
    }
}
