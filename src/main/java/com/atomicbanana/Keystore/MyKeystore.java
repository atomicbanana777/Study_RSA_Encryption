package com.atomicbanana.Keystore;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Properties;

public class MyKeystore {
    
    private Properties prop;

    public MyKeystore() throws IOException{
        prop = new Properties();
        prop.load(getClass().getClassLoader().getResourceAsStream("propertiesFile.prop"));
    }

    public String getKeystorePW() throws IOException{
        byte[] pw = Base64.getDecoder().decode(prop.getProperty("keystorePW"));
        return new String(pw);
    }

    public KeyStore loadKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
        ClassLoader classLoader = getClass().getClassLoader();
        char[] pwdArray = getKeystorePW().toCharArray();
        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(classLoader.getResourceAsStream(prop.getProperty("keystore")), pwdArray);
        return ks;
    }

    public PrivateKey getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
        KeyStore ks = loadKeystore();
        Key key = ks.getKey(prop.getProperty("private"), getKeystorePW().toCharArray());

        return (PrivateKey) key;
    }

    public PublicKey getPublicKey() throws CertificateException{
        return getCert().getPublicKey();
    }

    public Certificate getCert() throws CertificateException{
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        ClassLoader classLoader = getClass().getClassLoader();
        Certificate cert = fac.generateCertificate(classLoader.getResourceAsStream(prop.getProperty("public")));
        return cert;
    }
}
