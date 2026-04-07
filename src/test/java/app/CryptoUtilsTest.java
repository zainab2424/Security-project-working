package app;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

// Tests core wrapping and decryption behavior in CryptoUtils.
class CryptoUtilsTest {
    @Test
     // Intended recipient should be able to unwrap and decrypt successfully.
    void wrapsUnwrapsAndDecryptsForIntendedRecipient() throws Exception {
        var recipient = TestFixtures.fixedBobClient();
        byte[] plaintext = TestFixtures.SAMPLE_CONTRACT;

        SecretKey fileKey = CryptoUtils.generateAesKey();
        CryptoUtils.AesGcmBlob encrypted = CryptoUtils.aesGcmEncrypt(fileKey, plaintext);
        CryptoUtils.WrappedKey wrapped = CryptoUtils.wrapAesKeyForRecipient(
                recipient.publicKey(),
                fileKey,
                new java.security.SecureRandom()
        );

        SecretKey unwrapped = CryptoUtils.unwrapAesKey(recipient.privateKey(), wrapped);
        byte[] decrypted = CryptoUtils.aesGcmDecrypt(unwrapped, encrypted.ivB64(), encrypted.ctB64());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    // Wrong private key should not unwrap the recipient's key.
    void wrongPrivateKeyCannotUnwrapRecipientKey() throws Exception {
        var recipient = TestFixtures.fixedBobClient();
        var wrongUser = TestFixtures.fixedAliceLawyer();

        SecretKey fileKey = CryptoUtils.generateAesKey();
        CryptoUtils.WrappedKey wrapped = CryptoUtils.wrapAesKeyForRecipient(
                recipient.publicKey(),
                fileKey,
                new java.security.SecureRandom()
        );

        assertThrows(AEADBadTagException.class, () -> CryptoUtils.unwrapAesKey(wrongUser.privateKey(), wrapped));
    }
}
