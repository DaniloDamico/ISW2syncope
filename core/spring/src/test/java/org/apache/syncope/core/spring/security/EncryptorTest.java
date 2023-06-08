package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptorTest {

    @Test
    public void testEncryptor() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Encryptor encryptor = Encryptor.getInstance();
        String encrypted = encryptor.encode("password", CipherAlgorithm.AES);
        Assert.assertEquals("password", encryptor.decode(encrypted, CipherAlgorithm.AES));
    }

}
