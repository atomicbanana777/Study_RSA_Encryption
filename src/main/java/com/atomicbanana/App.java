package com.atomicbanana;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.atomicbanana.Keystore.MyKeystore;
import com.atomicbanana.RSAEncryptor.RSAEncryptor;
import com.atomicbanana.RSAEncryptor.RSAKeyGenerator;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeySpecException, CertificateException, UnrecoverableKeyException, KeyStoreException
    {
        if(args.length == 0){
            System.out.println("hi, you can use following options:");
            System.out.println("genKeyPair");
            System.out.println("encrypt <publicKey path> <data to encrypt>");
            System.out.println("decrypt <privateKey path> <data to decrypt>");
            System.out.println("encryptByCert <data to encrypt>");
            System.out.println("decryptByCert <data to decrypt>");
        }

        if(args.length == 1 && args[0].equals("genKeyPair")){
            RSAKeyGenerator keyGenerator = new RSAKeyGenerator();
            keyGenerator.writeToFile("RSA/publicKey", Base64.getEncoder().encodeToString(keyGenerator.getPublicKey().getEncoded()));
            System.out.println("Public key generated in RSA/publicKey");
            keyGenerator.writeToFile("RSA/privateKey", Base64.getEncoder().encodeToString(keyGenerator.getPrivateKey().getEncoded()));
            System.out.println("Privatec key generated in RSA/privateKey");
        }

        if(args.length == 3 && args[0].equals("decrypt")){
            byte[] encryptedData = Base64.getDecoder().decode(args[2]);
            byte[] result = RSAEncryptor.decrypt(encryptedData, RSAEncryptor.getPrivateKeyFromFile(args[1]));
            System.out.println("decrypted: " + new String(result));
        }

        if(args.length == 3 && args[0].equals("encrypt")){

            byte[] result = RSAEncryptor.encrypt(args[2], RSAEncryptor.getPublicKeyFromFile(args[1]));
            System.out.println("encrypted: " + Base64.getEncoder().encodeToString(result));
        }

        if(args.length == 2 && args[0].equals("encryptByCert")){
            MyKeystore ks = new MyKeystore();
            byte[] result = RSAEncryptor.encrypt(args[1], ks.getPublicKey());
            System.out.println("encrypted: " + Base64.getEncoder().encodeToString(result));
        }

        if(args.length == 2 && args[0].equals("decryptByCert")){
            byte[] encryptedData = Base64.getDecoder().decode(args[1]);
            MyKeystore ks = new MyKeystore();
            byte[] result = RSAEncryptor.decrypt(encryptedData, ks.getPrivateKey());
            System.out.println("decrypted: " + new String(result));
        }
    }
    
}
