package app;

import java.security.GeneralSecurityException;

public final class OtUtils {
    public static final String OT_PROTOCOL_TAG = "OT_STYLE_TRANSFER_V1";
    public static final String CHOICE_REAL = "REAL";
    public static final String CHOICE_BOGUS = "BOGUS";

    private OtUtils() {}

    public record Offer(String protocolTag, String transferId, String realCommitmentB64, String bogusCommitmentB64) {}

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

    public static String commitmentForChoice(String transferId, String choice, String wrapCtB64) throws GeneralSecurityException {
        String normalizedChoice = normalizeChoice(choice);
        return digestB64("OT_COMMIT|" + transferId + "|" + normalizedChoice + "|" + wrapCtB64);
    }

    public static String selectionPayload(String contractId, String transferId, String choice, String timestampIso) {
        return "OT_SELECT|" + contractId + "|" + transferId + "|" + normalizeChoice(choice) + "|" + timestampIso;
    }

    public static String normalizeChoice(String choice) {
        if (choice == null) throw new IllegalArgumentException("OT choice required");
        String normalized = choice.trim().toUpperCase();
        if (!CHOICE_REAL.equals(normalized) && !CHOICE_BOGUS.equals(normalized)) {
            throw new IllegalArgumentException("Invalid OT choice");
        }
        return normalized;
    }

    private static String digestB64(String value) throws GeneralSecurityException {
        return CryptoUtils.b64(CryptoUtils.sha256(CryptoUtils.utf8(value)));
    }
}
