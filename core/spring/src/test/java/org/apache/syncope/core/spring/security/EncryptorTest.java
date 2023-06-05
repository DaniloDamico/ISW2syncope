package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.security.Encryptor;
import org.junit.Assert;
import org.junit.Test;

public class EncryptorTest {

    @Test
    public void testEncodeAndVerify() {
        Encryptor encryptor = Encryptor.getInstance();

        String value = "password";
        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;

        try {
            String encoded = encryptor.encode(value, cipherAlgorithm);
            boolean verified = encryptor.verify(value, cipherAlgorithm, encoded);

            Assert.assertTrue(verified);
        } catch (Exception e) {
            Assert.fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testDecode() {
        Encryptor encryptor = Encryptor.getInstance();

        String value = "password";
        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES;

        try {
            String encoded = encryptor.encode(value, cipherAlgorithm);
            String decoded = encryptor.decode(encoded, cipherAlgorithm);

            Assert.assertEquals(value, decoded);
        } catch (Exception e) {
            Assert.fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testEncodeAndVerifyWithBCrypt() {
        Encryptor encryptor = Encryptor.getInstance();

        String value = "password";
        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.BCRYPT;

        try {
            String encoded = encryptor.encode(value, cipherAlgorithm);
            boolean verified = encryptor.verify(value, cipherAlgorithm, encoded);

            Assert.assertTrue(verified);
        } catch (Exception e) {
            Assert.fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testEncodeAndVerifyWithSHA1() {
        Encryptor encryptor = Encryptor.getInstance();

        String value = "password";
        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.SHA1;

        try {
            String encoded = encryptor.encode(value, cipherAlgorithm);
            boolean verified = encryptor.verify(value, cipherAlgorithm, encoded);

            Assert.assertTrue(verified);
        } catch (Exception e) {
            Assert.fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testEncodeAndVerifyWithSHA256() {
        Encryptor encryptor = Encryptor.getInstance();

        String value = "password";
        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.SHA256;

        try {
            String encoded = encryptor.encode(value, cipherAlgorithm);
            boolean verified = encryptor.verify(value, cipherAlgorithm, encoded);

            Assert.assertTrue(verified);
        } catch (Exception e) {
            Assert.fail("Exception occurred: " + e.getMessage());
        }
    }
}
