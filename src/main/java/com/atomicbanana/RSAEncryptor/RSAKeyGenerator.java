package com.atomicbanana.RSAEncryptor;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAKeyGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void writeToFile(String path, String base64Key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        BufferedWriter writer = new BufferedWriter(new FileWriter(f));
        writer.write(base64Key);
        writer.close();
    }
}
