package com.atomicbanana.RSAEncryptor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAEncryptor {
    
    public static byte[] encrypt(String data, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static PublicKey getPublicKeyFromFile(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File keyFile = new File(path);
        return getPublicKey(Files.readString(keyFile.toPath()));
    }
    
    public static PublicKey getPublicKey(String base64PublicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return factory.generatePublic(publicKeySpec);
    }

    public static PrivateKey getPrivateKeyFromFile(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        File keyFile = new File(path);
        return getPrivateKey(Files.readString(keyFile.toPath()));
    }
    
    public static PrivateKey getPrivateKey(String base64PrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return factory.generatePrivate(privateKeySpec);
    }
}
