package com.atomicbanana;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.atomicbanana.RSAEncryptor.RSAEncryptor;
import com.atomicbanana.RSAEncryptor.RSAKeyGenerator;

public class TestWithTempRSAKey {

    File publicKeyFile, privateKeyFile;

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void setUp() throws NoSuchAlgorithmException, IOException {
        File RSAFolder = folder.newFolder("RSA");
        RSAFolder.mkdir();
        publicKeyFile = folder.newFile( "RSA/publicKey" );
        privateKeyFile = folder.newFile( "RSA/privateKey" );
        RSAKeyGenerator keyGenerator = new RSAKeyGenerator();
        keyGenerator.writeToFile(publicKeyFile.getPath(), Base64.getEncoder().encodeToString(keyGenerator.getPublicKey().getEncoded()));
        keyGenerator.writeToFile(privateKeyFile.getPath(), Base64.getEncoder().encodeToString(keyGenerator.getPrivateKey().getEncoded()));
    }

    @Test
    public void encryptFromFileCorrectly() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, IOException
    {
        String data = "Something I need to encrypt";
        PublicKey publicKey = RSAEncryptor.getPublicKeyFromFile(publicKeyFile.getPath());
        PrivateKey privateKey = RSAEncryptor.getPrivateKeyFromFile(privateKeyFile.getPath());

        byte[] encrypted = RSAEncryptor.encrypt(data, publicKey);
        byte[] decrypted = RSAEncryptor.decrypt(encrypted, privateKey);

        assertEquals(data, new String(decrypted));
    }
}
