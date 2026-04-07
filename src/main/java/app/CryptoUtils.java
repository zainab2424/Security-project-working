package app;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/*
 * CryptoUtils contains shared cryptographic helper methods used by the system.
 * It supports key generation, signing, verification, hashing, encryption, and key wrapping.
 */

public final class CryptoUtils {
    private CryptoUtils() {}

    // ==== Keys ====

    /* Generates an EC key pair using the NIST P-256 curve. */
    public static KeyPair generateECKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        // NIST P-256
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    /* Encodes bytes as Base64 text. */
    public static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /* Decodes Base64 text into bytes. */
    public static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    /* Converts a public key to encoded X.509 bytes. */
    public static byte[] publicKeyToBytes(PublicKey pk) {
        return pk.getEncoded(); // X.509
    }

    /* Rebuilds a public key from encoded X.509 bytes. */
    public static PublicKey bytesToPublicKey(byte[] enc) throws GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(enc);
        return KeyFactory.getInstance("EC").generatePublic(spec);
    }

    /* Converts a private key to encoded PKCS#8 bytes. */
    public static byte[] privateKeyToBytes(PrivateKey sk) {
        return sk.getEncoded(); // PKCS#8
    }

    /* Rebuilds a private key from encoded PKCS#8 bytes. */
    public static PrivateKey bytesToPrivateKey(byte[] enc) throws GeneralSecurityException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(enc);
        return KeyFactory.getInstance("EC").generatePrivate(spec);
    }

    // ==== Signatures ====

    /* Signs a message using ECDSA with SHA-256. */
    public static byte[] sign(PrivateKey sk, byte[] message) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(sk);
        sig.update(message);
        return sig.sign();
    }

    /*
     * Verifies an ECDSA signature.
     * Converts raw WebCrypto P-256 signatures to DER format when needed.
     */
    public static boolean verify(PublicKey pk, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(pk);
        sig.update(message);

        // WebCrypto ECDSA signatures are returned as raw r||s (64 bytes for P-256).
        // Java's SHA256withECDSA expects an ASN.1/DER encoded signature.
        byte[] maybeDer = (signature != null && signature.length == 64)
                ? rawEcdsaP256ToDer(signature)
                : signature;

        return sig.verify(maybeDer);
    }

    /* Converts a raw P-256 signature into DER format for Java verification. */
    private static byte[] rawEcdsaP256ToDer(byte[] raw) {
        if (raw == null || raw.length != 64) return raw;

        byte[] r = Arrays.copyOfRange(raw, 0, 32);
        byte[] s = Arrays.copyOfRange(raw, 32, 64);

        r = stripLeadingZeros(r);
        s = stripLeadingZeros(s);

        // If highest bit set, prefix 0x00 to keep INTEGER positive
        if ((r[0] & 0x80) != 0) r = concat(new byte[]{0x00}, r);
        if ((s[0] & 0x80) != 0) s = concat(new byte[]{0x00}, s);

        int len = 2 + r.length + 2 + s.length;
        // For P-256, len always fits in one byte.
        byte[] der = new byte[2 + len];

        int i = 0;
        der[i++] = 0x30;              // SEQUENCE
        der[i++] = (byte) len;

        der[i++] = 0x02;              // INTEGER
        der[i++] = (byte) r.length;
        System.arraycopy(r, 0, der, i, r.length);
        i += r.length;

        der[i++] = 0x02;              // INTEGER
        der[i++] = (byte) s.length;
        System.arraycopy(s, 0, der, i, s.length);

        return der;
    }

    /* Removes leading zero bytes from a big-endian integer representation. */
    private static byte[] stripLeadingZeros(byte[] x) {
        int i = 0;
        while (i < x.length - 1 && x[i] == 0x00) i++;
        return Arrays.copyOfRange(x, i, x.length);
    }

    /* Concatenates two byte arrays. */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ==== Hashing ====

    /* Computes a SHA-256 hash. */
    public static byte[] sha256(byte[] data) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // ==== Symmetric Encryption (AES-GCM) ====

    /* Generates a random 256-bit AES key. */
    public static SecretKey generateAesKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    /* Stores AES-GCM output as Base64 IV and ciphertext. */
    public static record AesGcmBlob(String ivB64, String ctB64) {}

    /* Encrypts plaintext with AES-GCM and returns the IV and ciphertext. */
    public static AesGcmBlob aesGcmEncrypt(SecretKey key, byte[] plaintext) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);
        return new AesGcmBlob(b64(iv), b64(ct));
    }

    /* Decrypts AES-GCM ciphertext using the supplied key and IV. */
    public static byte[] aesGcmDecrypt(SecretKey key, String ivB64, String ctB64) throws GeneralSecurityException {
        byte[] iv = b64d(ivB64);
        byte[] ct = b64d(ctB64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

    // ==== Key wrapping using ECDH + AES-GCM ====
    // Instead of RSA-wrapping, we use a modern pattern:
    // ephemeral ECDH to derive a wrapping key and encrypt the AES file key.

    /* Stores wrapped key material and the ephemeral public key used to derive it. */
    public static record WrappedKey(String ephPubB64, String wrapIvB64, String wrapCtB64) {}

    /*
     * Wraps an AES file key for a recipient using ephemeral ECDH and AES-GCM.
     * The recipient can later derive the same wrapping key using their private key.
     */
    public static WrappedKey wrapAesKeyForRecipient(PublicKey recipientPk, SecretKey fileKey, SecureRandom rnd)
            throws GeneralSecurityException {
        // ephemeral keypair
        KeyPair eph = generateECKeyPair();

        // EC
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(recipientPk, true);
        byte[] shared = ka.generateSecret();

        // derive a wrapping key from shared secret (simple KDF: SHA-256)
        byte[] kdf = sha256(shared);
        SecretKey wrapKey = new javax.crypto.spec.SecretKeySpec(Arrays.copyOf(kdf, 32), "AES");

        // encrypt raw AES key bytes
        byte[] rawFileKey = fileKey.getEncoded();
        AesGcmBlob blob = aesGcmEncrypt(wrapKey, rawFileKey);

        return new WrappedKey(
                b64(publicKeyToBytes(eph.getPublic())),
                blob.ivB64(),
                blob.ctB64()
        );
    }

    /* Unwraps an AES file key using the recipient's private key and stored wrapped data. */
    public static SecretKey unwrapAesKey(PrivateKey recipientSk, WrappedKey wrapped) throws GeneralSecurityException {
        PublicKey ephPk = bytesToPublicKey(b64d(wrapped.ephPubB64()));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(recipientSk);
        ka.doPhase(ephPk, true);
        byte[] shared = ka.generateSecret();

        byte[] kdf = sha256(shared);
        SecretKey wrapKey = new javax.crypto.spec.SecretKeySpec(Arrays.copyOf(kdf, 32), "AES");

        byte[] raw = aesGcmDecrypt(wrapKey, wrapped.wrapIvB64(), wrapped.wrapCtB64());
        return new javax.crypto.spec.SecretKeySpec(raw, "AES");
    }

    // ==== Misc ====

    /* Returns the current timestamp in ISO-8601 format. */
    public static String nowIso() {
        return Instant.now().toString();
    }

    /* Converts a string to UTF-8 bytes. */
    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /* Converts UTF-8 bytes to a string. */
    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
