package app;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptoUtilsTest {
    @Test
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
