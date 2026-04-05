package app;

import app.CryptoUtils.WrappedKey;
import app.Protocol.Msg;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class RecipientClientMain {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5050;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: RecipientClientMain <recipientUser>");
            return;
        }
        String recipient = args[0];

        KeyPair recipientKeys = LocalKeys.loadOrCreate(recipient);

        // Register recipient public key with server
        ServerApi.register(recipient, recipientKeys.getPublic());
        System.out.println("Recipient registered and ready.");

        // Use try-with-resources to avoid resource leak warning
        try (Scanner sc = new Scanner(System.in)) {
            System.out.print("Enter contractId to fetch: ");
            String contractId = sc.nextLine().trim();

            // 1) Fetch encrypted contract
            Msg contract = ServerApi.authAndGetContract(recipient, recipientKeys, contractId);
            System.out.println("Fetched encrypted contract: " + contract.filename + " from " + contract.from);

            // 2) Create and submit receipt (sign)
            String ts = CryptoUtils.nowIso();
            String receiptPayload = "RECEIPT|" + contractId + "|" + contract.contractHashB64 + "|" + ts;
            byte[] receiptSig = CryptoUtils.sign(recipientKeys.getPrivate(), CryptoUtils.utf8(receiptPayload));

            boolean submitted = ServerApi.authAndSubmitReceipt(recipient, recipientKeys, contractId, ts, receiptSig);
            if (!submitted) {
                System.out.println("Receipt submission failed.");
                return;
            }
            System.out.println("Receipt submitted. Key should now be released.");

            // 3) Complete OT-style selection if the contract uses it
            Msg otOffer = ServerApi.authAndGetOtOffer(recipient, recipientKeys, contractId);
            if ("OT_OFFER_DATA".equals(otOffer.type)) {
                String otTs = CryptoUtils.nowIso();
                String otPayload = OtUtils.selectionPayload(contractId, otOffer.otTransferId, OtUtils.CHOICE_REAL, otTs);
                byte[] otSig = CryptoUtils.sign(recipientKeys.getPrivate(), CryptoUtils.utf8(otPayload));
                boolean otSubmitted = ServerApi.authAndSubmitOtSelection(
                        recipient,
                        recipientKeys,
                        contractId,
                        otOffer.otProtocolTag,
                        otOffer.otTransferId,
                        OtUtils.CHOICE_REAL,
                        otTs,
                        otSig
                );
                if (!otSubmitted) {
                    System.out.println("OT selection failed.");
                    return;
                }
                System.out.println("OT selection recorded.");
            }

            // 4) Get released wrapped key
            Msg keyMsg = ServerApi.authAndGetReleasedKey(recipient, recipientKeys, contractId);

            WrappedKey wrapped = new WrappedKey(keyMsg.ephPubB64, keyMsg.wrapIvB64, keyMsg.wrapCtB64);
            SecretKey fileKey = CryptoUtils.unwrapAesKey(recipientKeys.getPrivate(), wrapped);

            // 5) Decrypt file
            byte[] plaintext = CryptoUtils.aesGcmDecrypt(fileKey, contract.contractIvB64, contract.contractCtB64);

            // 6) Verify hash matches
            byte[] h = CryptoUtils.sha256(plaintext);
            String hB64 = CryptoUtils.b64(h);
            if (!hB64.equals(contract.contractHashB64)) {
                System.out.println("INTEGRITY FAIL! Hash mismatch. Expected " + contract.contractHashB64 + " got " + hB64);
                return;
            }
            System.out.println("Integrity OK. Decrypted successfully.");

            File outDir = new File("downloads");
            outDir.mkdirs();
            File out = new File(outDir, "DECRYPTED_" + contract.filename);
            Files.write(out.toPath(), plaintext);
            System.out.println("Saved decrypted contract to: " + out.getPath());
        }
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
    }

    static class ServerApi {
        static void register(String user, PublicKey pk) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                Msg reg = new Msg();
                reg.type = "REGISTER";
                reg.from = user;
                reg.publicKeyB64 = CryptoUtils.b64(CryptoUtils.publicKeyToBytes(pk));
                NetUtils.sendJson(s, reg);
                NetUtils.readJson(s, Msg.class);
            }
        }

        static void doAuth(java.net.Socket s, String user, KeyPair keys) throws Exception {
            Msg start = new Msg();
            start.type = "AUTH_START";
            start.from = user;
            NetUtils.sendJson(s, start);

            Msg chal = NetUtils.readJson(s, Msg.class);
            if (!"AUTH_CHALLENGE".equals(chal.type)) {
                throw new RuntimeException("Expected AUTH_CHALLENGE, got: " + chal.type);
            }

            byte[] sig = CryptoUtils.sign(keys.getPrivate(), CryptoUtils.b64d(chal.nonceB64));
            Msg prove = new Msg();
            prove.type = "AUTH_PROVE";
            prove.from = user;
            prove.signatureB64 = CryptoUtils.b64(sig);
            NetUtils.sendJson(s, prove);

            Msg ok = NetUtils.readJson(s, Msg.class);
            if (!"AUTH_OK".equals(ok.type)) {
                throw new RuntimeException("Auth failed: " + ok.error);
            }
        }

        static Msg authAndGetContract(String user, KeyPair keys, String contractId) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                doAuth(s, user, keys);

                Msg req = new Msg();
                req.type = "GET_CONTRACT";
                req.from = user;
                req.contractId = contractId;

                NetUtils.sendJson(s, req);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"CONTRACT_DATA".equals(resp.type)) {
                    throw new RuntimeException("Get contract failed: " + resp.error);
                }
                return resp;
            }
        }

        static boolean authAndSubmitReceipt(String user, KeyPair keys, String contractId, String tsIso, byte[] sig) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                doAuth(s, user, keys);

                Msg req = new Msg();
                req.type = "SUBMIT_RECEIPT";
                req.from = user;
                req.contractId = contractId;
                req.timestampIso = tsIso;
                req.signatureB64 = CryptoUtils.b64(sig);

                NetUtils.sendJson(s, req);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"RECEIPT_OK".equals(resp.type)) {
                    System.out.println("Receipt error: " + resp.error);
                    return false;
                }
                return true;
            }
        }

        static Msg authAndGetReleasedKey(String user, KeyPair keys, String contractId) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                doAuth(s, user, keys);

                Msg req = new Msg();
                req.type = "GET_RELEASED_KEY";
                req.from = user;
                req.contractId = contractId;

                NetUtils.sendJson(s, req);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"RELEASED_KEY".equals(resp.type)) {
                    throw new RuntimeException("Key not released: " + resp.error);
                }
                return resp;
            }
        }

        static Msg authAndGetOtOffer(String user, KeyPair keys, String contractId) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                doAuth(s, user, keys);

                Msg req = new Msg();
                req.type = "GET_OT_OFFER";
                req.from = user;
                req.contractId = contractId;

                NetUtils.sendJson(s, req);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if ("OT_OFFER_DATA".equals(resp.type)) return resp;
                if ("ERR".equals(resp.type) && "OT not enabled for this contract".equals(resp.error)) return resp;
                throw new RuntimeException("Get OT offer failed: " + resp.error);
            }
        }

        static boolean authAndSubmitOtSelection(String user,
                                                KeyPair keys,
                                                String contractId,
                                                String otProtocolTag,
                                                String otTransferId,
                                                String otSelection,
                                                String tsIso,
                                                byte[] sig) throws Exception {
            try (var s = new java.net.Socket(HOST, PORT)) {
                doAuth(s, user, keys);

                Msg req = new Msg();
                req.type = "SUBMIT_OT_SELECTION";
                req.from = user;
                req.contractId = contractId;
                req.otProtocolTag = otProtocolTag;
                req.otTransferId = otTransferId;
                req.otSelection = otSelection;
                req.timestampIso = tsIso;
                req.signatureB64 = CryptoUtils.b64(sig);

                NetUtils.sendJson(s, req);
                Msg resp = NetUtils.readJson(s, Msg.class);
                if (!"OT_SELECTION_OK".equals(resp.type)) {
                    System.out.println("OT selection error: " + resp.error);
                    return false;
                }
                return true;
            }
        }
    }
}
