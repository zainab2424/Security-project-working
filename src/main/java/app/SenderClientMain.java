package app;

import app.Protocol.Msg;
import app.CryptoUtils.WrappedKey;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;

public class SenderClientMain {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5050;
    private static final String BOGUS_ARTIFACT_TAG = "BOGUS_CERTIFIED_ARTIFACT_V1";

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: SenderClientMain <senderUser> <recipientUser> <pathToContractFile>");
            return;
        }
        String sender = args[0];
        String recipient = args[1];
        File contractFile = new File(args[2]);

        // Load or create sender keys (local file storage)
        KeyPair senderKeys = LocalKeys.loadOrCreate(sender);

        // Ensure recipient public key exists on server (recipient must register first)
        // Sender registers itself too (safe to re-register).
        ServerApi.register(sender, senderKeys.getPublic());

        byte[] plaintext = Files.readAllBytes(contractFile.toPath());
        byte[] contractHash = CryptoUtils.sha256(plaintext);

        SecretKey fileKey = CryptoUtils.generateAesKey();
        CryptoUtils.AesGcmBlob enc = CryptoUtils.aesGcmEncrypt(fileKey, plaintext);
        byte[] bogusPlaintext = CryptoUtils.utf8(
                BOGUS_ARTIFACT_TAG + "\nThis is a bogus protected message.\nOriginal file: "
                        + contractFile.getName() + "\nNonce: " + java.util.UUID.randomUUID()
        );
        byte[] bogusHash = CryptoUtils.sha256(bogusPlaintext);
        SecretKey bogusFileKey = CryptoUtils.generateAesKey();
        CryptoUtils.AesGcmBlob bogusEnc = CryptoUtils.aesGcmEncrypt(bogusFileKey, bogusPlaintext);

        // Fetch recipient public key by asking user to paste it? (Too annoying)
        // Instead: this demo expects recipient already registered; server doesn't expose pubkeys publicly.
        // Workaround for a simple course project: store recipient pubkey locally too (generated on recipient client)
        PublicKey recipientPk = LocalKeys.loadPublic(recipient);

        WrappedKey wrapped = CryptoUtils.wrapAesKeyForRecipient(recipientPk, fileKey, new java.security.SecureRandom());
        WrappedKey bogusWrapped = CryptoUtils.wrapAesKeyForRecipient(recipientPk, bogusFileKey, new java.security.SecureRandom());

        // Upload ciphertext + wrapped key to server AFTER authenticating
        Msg upload = new Msg();
        upload.type = "UPLOAD_CONTRACT";
        upload.from = sender;
        upload.to = recipient;
        upload.filename = contractFile.getName();
        upload.contractIvB64 = enc.ivB64();
        upload.contractCtB64 = enc.ctB64();
        upload.contractHashB64 = CryptoUtils.b64(contractHash);
        upload.bogusArtifactTag = BOGUS_ARTIFACT_TAG;
        upload.bogusContractIvB64 = bogusEnc.ivB64();
        upload.bogusContractCtB64 = bogusEnc.ctB64();
        upload.bogusContractHashB64 = CryptoUtils.b64(bogusHash);
        upload.ephPubB64 = wrapped.ephPubB64();
        upload.wrapIvB64 = wrapped.wrapIvB64();
        upload.wrapCtB64 = wrapped.wrapCtB64();
        upload.bogusEphPubB64 = bogusWrapped.ephPubB64();
        upload.bogusWrapIvB64 = bogusWrapped.wrapIvB64();
        upload.bogusWrapCtB64 = bogusWrapped.wrapCtB64();

        String contractId = ServerApi.authAndUpload(sender, senderKeys, upload);
        System.out.println("Uploaded contract. contractId=" + contractId);
        System.out.println("Recipient must submit receipt before key is released.");
        System.out.println("Done.");
    }

    // Minimal local key storage helper
    static class LocalKeys {
        static KeyPair loadOrCreate(String user) throws Exception {
            File dir = new File("keys");
            dir.mkdirs();
            File privF = new File(dir, user + ".priv");
            File pubF = new File(dir, user + ".pub");

            if (privF.exists() && pubF.exists()) {
                byte[] priv = Files.readAllBytes(privF.toPath());
                byte[] pub = Files.readAllBytes(pubF.toPath());
                return new KeyPair(CryptoUtils.bytesToPublicKey(pub), CryptoUtils.bytesToPrivateKey(priv));
            }

            KeyPair kp = CryptoUtils.generateECKeyPair();
            Files.write(privF.toPath(), CryptoUtils.privateKeyToBytes(kp.getPrivate()));
            Files.write(pubF.toPath(), CryptoUtils.publicKeyToBytes(kp.getPublic()));
            return kp;
        }

        static PublicKey loadPublic(String user) throws Exception {
            File pubF = new File("keys/" + user + ".pub");
            if (!pubF.exists()) {
                System.out.println("Missing recipient public key file: " + pubF.getPath());
                System.out.println("Run recipient once to generate keys and register.");
                System.exit(1);
            }
            return CryptoUtils.bytesToPublicKey(Files.readAllBytes(pubF.toPath()));
        }
    }

    static class ServerApi {
        static void register(String user, PublicKey pk) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                Msg reg = new Msg();
                reg.type = "REGISTER";
                reg.from = user;
                reg.publicKeyB64 = CryptoUtils.b64(CryptoUtils.publicKeyToBytes(pk));
                NetUtils.sendJson(s, reg);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"REGISTER_OK".equals(resp.type)) {
                    System.out.println("Register response: " + resp.type + " err=" + resp.error);
                }
            }
        }

        static String authAndUpload(String user, KeyPair keys, Msg upload) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                // AUTH_START
                Msg start = new Msg(); start.type="AUTH_START"; start.from=user;
                NetUtils.sendJson(s, start);

                Msg chal = NetUtils.readJson(s, Msg.class);
                if (!"AUTH_CHALLENGE".equals(chal.type)) throw new RuntimeException("No challenge");

                byte[] sig = CryptoUtils.sign(keys.getPrivate(), CryptoUtils.b64d(chal.nonceB64));
                Msg prove = new Msg(); prove.type="AUTH_PROVE"; prove.from=user; prove.signatureB64 = CryptoUtils.b64(sig);
                NetUtils.sendJson(s, prove);

                Msg ok = NetUtils.readJson(s, Msg.class);
                if (!"AUTH_OK".equals(ok.type)) throw new RuntimeException("Auth failed: " + ok.error);

                NetUtils.sendJson(s, upload);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"UPLOAD_OK".equals(resp.type)) throw new RuntimeException("Upload failed: " + resp.error);
                return resp.contractId;
            }
        }
    }
}
