package com.atomicbanana;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Test;

import com.atomicbanana.Keystore.MyKeystore;
import com.atomicbanana.RSAEncryptor.RSAEncryptor;
import com.atomicbanana.RSAEncryptor.RSAKeyGenerator;

/**
 * Unit test for simple App.
 */
public class AppTest 
{

    private final String privateKey_base64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAINkXvIdP4GuebNtaYq9sOA7Je6h6AG" + 
    "fFZSpBGgCY0XnO7kjw53KNfe540wUU0KFPmlYo8IUjX1M27Ggy4LBh4f6AMRzIAGnAXuNRptleQPl3bNYuXHyxy" +
    "NZOJQvqXmJKzSO2BA1Gm5sYnrD4WrR4X/wIYNPielgfCAch/jqP7plAgMBAAECgYA83o3hykz2bfbxebmQTcqYRq6O+7" +
    "C4t5NO2HIzIRAOfU48ueXQvrH7vsEfKLddtM6yDR9oNQ9LQgTxKFW/kJqRZ/YTA+TnlIU1qmZJ5i1ULBmkz4KGANbfMGYVZN" +
    "flwrixh65LZMbp1Jwm9X5Nqva6gjv3ZR3SrMecSWvGtHQoLQJBAKQsBpkBSmPsNxhxwzGw65WROAX2PaKjD2Oi9f20fQSdz5Fx78C61i" +
    "Py08ACjKNJDjsr+0cJc2oFDAjZnj9iWE8CQQDM4o2fO4Pf6MEGD/U2YHBl1dZv0OBjOSp0CO8XU6EJA18AA6ilQkFYkQM0KF39c4IzLiEU" + 
    "UkolSxjkJmxFcGELAkBO3kedIZ2XO1eMirp3GMNUaxs64fziMOunthXu99JHcXjSKqY/NILDaliHmbHuj54ilxJ0IfosKJiLd+AqGxjJAkEAtZde+n" +
    "Cfc4cx/ZOLPMTBGiErTDOPjaIPNITulHg01G4+dx7HDKHqlPsCIepdU9Ra483Q19gPi3pB94TulaUC/QJAROjd9DDBuyxeQGYVtTo1/JCxVkPJgrIwGg" +
    "JoaqHYa28vETsPZyscKZyHfsHfl1j5WGlWpYRbYBIf0mOo1f5o8g==";

    private final String publicKey_base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDZF7yHT+BrnmzbWmKvbDgOyXu" + 
    "oegBnxWUqQRoAmNF5zu5I8OdyjX3ueNMFFNChT5pWKPCFI19TNuxoMuCwYeH+gDEcyABpwF7jUabZXkD5d2zWLlx8scjWTiUL6l5iSs0jtgQNRpubGJ6w+Fq0eF/8CGDT4npYHwgHIf46j+6ZQIDAQAB";
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue()
    {
        assertTrue( true );
    }

    @Test
    public void encryptCorrectly() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException
    {
        String data = "Something I need to encrypt";
        RSAKeyGenerator keyGenerator = new RSAKeyGenerator();
        byte[] encrypted = RSAEncryptor.encrypt(data, keyGenerator.getPublicKey());
        byte[] decrypted = RSAEncryptor.decrypt(encrypted, keyGenerator.getPrivateKey());

        assertEquals(data, new String(decrypted));
    }

    @Test
    public void encryptFromStringCorrectly() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, IOException
    {
        String data = "Something I need to encrypt";
        PublicKey publicKey = RSAEncryptor.getPublicKey(publicKey_base64);
        PrivateKey privateKey = RSAEncryptor.getPrivateKey(privateKey_base64);

        byte[] encrypted = RSAEncryptor.encrypt(data, publicKey);
        byte[] decrypted = RSAEncryptor.decrypt(encrypted, privateKey);

        assertEquals(data, new String(decrypted));
    }

    @Test
    public void encryptFromKeyStoreCorrectly() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException
    {
        String data = "Something I need to encrypt";
        MyKeystore keystore = new MyKeystore();

        byte[] encrypted = RSAEncryptor.encrypt(data, keystore.getPublicKey());
        byte[] decrypted = RSAEncryptor.decrypt(encrypted, keystore.getPrivateKey());

        assertEquals(data, new String(decrypted));
    }

    @Test
    public void getKeystorePWCorrect() throws IOException 
    {
        String data = "password";
        MyKeystore keystore = new MyKeystore();
        assertEquals(data,keystore.getKeystorePW());
    }

}
