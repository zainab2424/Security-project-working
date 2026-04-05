package app;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Protocol {

    // ==== Common request envelope ====
    public static class Msg {
        public String type;
        public String from;
        public String to;

        // for auth handshake
        public String nonceB64;
        public String signatureB64;
        public String publicKeyB64;

        // contract delivery
        public String contractId;
        public String filename;
        public String contractIvB64;
        public String contractCtB64;
        public String contractHashB64;
        public String bogusArtifactTag;
        public String bogusContractIvB64;
        public String bogusContractCtB64;
        public String bogusContractHashB64;

        // wrapped file key (only released after receipt)
        public String ephPubB64;
        public String wrapIvB64;
        public String wrapCtB64;
        public String bogusEphPubB64;
        public String bogusWrapIvB64;
        public String bogusWrapCtB64;
        public String otProtocolTag;
        public String otTransferId;
        public String otRealCommitmentB64;
        public String otBogusCommitmentB64;
        public String otSelection;

        // receipt
        public String timestampIso;
        public Boolean receiptReceived;
        public Boolean decryptProofReceived;
        public String receiptTimestampIso;
        public String decryptProofTimestampIso;

        public String gatewayToken;

        // status
        public String ok;
        public String error;
    }

    public static class RegisteredUserKey {
        public String username;
        public String publicKeyB64;
    }

    public static class StoredContract {
        public String contractId;
        public String sender;
        public String recipient;
        public String filename;

        public String contractIvB64;
        public String contractCtB64;
        public String contractHashB64; // SHA-256 over plaintext
        public String bogusArtifactTag;
        public String bogusContractIvB64;
        public String bogusContractCtB64;
        public String bogusContractHashB64;

        public String ephPubB64;
        public String wrapIvB64;
        public String wrapCtB64;
        public String bogusEphPubB64;
        public String bogusWrapIvB64;
        public String bogusWrapCtB64;
        public String otProtocolTag;
        public String otTransferId;
        public String otRealCommitmentB64;
        public String otBogusCommitmentB64;
        public String otSelection;
        public String otSelectionSigB64;
        public String otSelectionTimestampIso;

        public boolean receiptReceived;
        public String receiptSigB64;
        public String receiptTimestampIso;

        public boolean decryptProofReceived;
        public String decryptProofSigB64;
        public String decryptProofTimestampIso;
        public String decryptWitnessHashB64;

    }
}
