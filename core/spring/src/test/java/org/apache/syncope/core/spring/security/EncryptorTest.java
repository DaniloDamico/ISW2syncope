package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.ConfigurableApplicationContext;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class EncryptorTest {

    String value;
    CipherAlgorithm cipherAlgorithm;
    boolean exception;

    @Mock
    ConfigurableApplicationContext applicationContext;

    //Category Partition
    //encode(final String value, final CipherAlgorithm cipherAlgorithm)
    //String value: null, empty, not empty
    //CipherAlgorithm cipherAlgorithm: SHA, SHA1, SHA256, SHA512, AES, SMD5, SSHA, SSHA1, SSHA256, SSHA512, BCRYPT

    @Parameters
    public static Collection<Object[]> getParameters(){

        String secretKey = "secret key";

        return Arrays.asList(new Object[][]{
                //value,    cipher,                 expectedException
                {secretKey, CipherAlgorithm.AES,    false},
                {"",        CipherAlgorithm.AES,    true},
                {null,      CipherAlgorithm.AES,    true},
                {secretKey, CipherAlgorithm.SHA,    false},
                {"",        CipherAlgorithm.SHA,    true},
                {null,      CipherAlgorithm.SHA,    true},
                {secretKey, CipherAlgorithm.SHA1,    false},
                {"",        CipherAlgorithm.SHA1,    true},
                {null,      CipherAlgorithm.SHA1,    true},
                {secretKey, CipherAlgorithm.SHA256,    false},
                {"",        CipherAlgorithm.SHA256,    true},
                {null,      CipherAlgorithm.SHA256,    true},
                {secretKey, CipherAlgorithm.SHA512,    false},
                {"",        CipherAlgorithm.SHA512,    true},
                {null,      CipherAlgorithm.SHA512,    true},
                {secretKey, CipherAlgorithm.SMD5,    false},
                {"",        CipherAlgorithm.SMD5,    true},
                {null,      CipherAlgorithm.SMD5,    true},
                {secretKey, CipherAlgorithm.SSHA,    false},
                {"",        CipherAlgorithm.SSHA,    true},
                {null,      CipherAlgorithm.SSHA,    true},
                {secretKey, CipherAlgorithm.SSHA1,    false},
                {"",        CipherAlgorithm.SSHA1,    true},
                {null,      CipherAlgorithm.SSHA1,    true},
                {secretKey, CipherAlgorithm.SSHA256,    false},
                {"",        CipherAlgorithm.SSHA256,    true},
                {null,      CipherAlgorithm.SSHA256,    true},
                {secretKey, CipherAlgorithm.SSHA512,    false},
                {"",        CipherAlgorithm.SSHA512,    true},
                {null,      CipherAlgorithm.SSHA512,    true},
                {secretKey, CipherAlgorithm.BCRYPT,    false},
                {"",        CipherAlgorithm.BCRYPT,    true},
                {null,      CipherAlgorithm.BCRYPT,    true},
                {null,      CipherAlgorithm.SSHA512,    true},
                {secretKey, null,                       true},
                {"",        null,                       true},
                {null,      null,                       true},
        });
    }

    public EncryptorTest(String value, final CipherAlgorithm cipherAlgorithm, boolean exception){
        this.exception = exception;
        this.value = value;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @Test
    public void testEncode() {
        try {
            Encryptor encryptor = Encryptor.getInstance();
            String encrypted = encryptor.encode(value, cipherAlgorithm);
            if(value == null) {
                Assert.assertNull(encrypted);
                return;
            }
            Assert.assertTrue(encryptor.verify(value, cipherAlgorithm, encrypted));
        }catch(Exception e){
            e.printStackTrace();
            Assert.assertTrue(exception);
        }
    }

    @Test
    public void testDecode() throws UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        Encryptor encryptor = Encryptor.getInstance();
        String encrypted = encryptor.encode(value, cipherAlgorithm);

        // only AES is invertible
        if (cipherAlgorithm == CipherAlgorithm.AES) {
            Assert.assertEquals(value, encryptor.decode(encrypted, cipherAlgorithm));
            return;
        }

        Assert.assertNull(encryptor.decode(encrypted, cipherAlgorithm));
    }

    @Test
    public void testEncodeWithEmptyKey() {
        try {
            Encryptor encryptor = Encryptor.getInstance("");
            String encrypted = encryptor.encode(value, cipherAlgorithm);
            if(value == null) {
                Assert.assertNull(encrypted);
                return;
            }
            Assert.assertTrue(encryptor.verify(value, cipherAlgorithm, encrypted));
        }catch(Exception e){
            e.printStackTrace();
            Assert.assertTrue(exception);
        }
    }

    @Test
    public void testEncodeWithKey() {
        try {
            Encryptor encryptor = Encryptor.getInstance("key");
            String encrypted = encryptor.encode(value, cipherAlgorithm);
            if(value == null) {
                Assert.assertNull(encrypted);
                return;
            }
            Assert.assertTrue(encryptor.verify(value, cipherAlgorithm, encrypted));
        }catch(Exception e){
            e.printStackTrace();
            Assert.assertTrue(exception);
        }
    }

    @Before
    public void setUp() {
        applicationContext = Mockito.mock(ConfigurableApplicationContext.class);
        SecurityProperties securityProperties = new SecurityProperties();
        when(applicationContext.getBean(SecurityProperties.class)).thenReturn(securityProperties);

        ApplicationContextProvider.setApplicationContext(applicationContext);
    }

}
