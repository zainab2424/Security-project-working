package app;

import com.fasterxml.jackson.annotation.JsonInclude;

/*
 * Protocol defines the shared message and storage structures used by the
 * web gateway, delivery server, and client code.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Protocol {

    // ==== Common request envelope ====
    public static class Msg {
        public String type;
        public String from;
        public String to;

        // Authentication fields
        public String nonceB64;
        public String signatureB64;
        public String publicKeyB64;

        // Contract delivery fields
        public String contractId;
        public String filename;
        public String contractIvB64;
        public String contractCtB64;
        public String contractHashB64;
        public String bogusArtifactTag;
        public String bogusContractIvB64;
        public String bogusContractCtB64;
        public String bogusContractHashB64;

        // Wrapped file key fields
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

        // Receipt and decrypt proof status fields
        public String timestampIso;
        public Boolean receiptReceived;
        public Boolean decryptProofReceived;
        public String receiptTimestampIso;
        public String decryptProofTimestampIso;

        // Trusted gateway field
        public String gatewayToken;

        // Generic status fields
        public String ok;
        public String error;
    }

    /* Stores a registered user's public key for persistence on the delivery server. */
    public static class RegisteredUserKey {
        public String username;
        public String publicKeyB64;
    }

     /* Stores one protected contract and all related protocol state. */
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
