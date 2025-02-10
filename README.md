# Study_RSA_Encryption
Study_RSA_Encryption

Study RSA Encryption in Java.

## About RSA 

  RSA is a asymmetrical encryption algorithm.
  
  It needs a public key and private key for encryption and decryption.
  
  While we can use Java program to generate a pair of public and private key,
  
  we usually use other tool such as `openssl` and `keytool` to output key pair.

## About the private and public key of this study

  I have generate a keystore for this repository `src/resources/study_rsa.keystore`

  and a public certificate `src/resources/public.cert`

  The keystore was generated by using `keytool`. It contains a private key.

  The public certificate was exported from the keystore using `keytool`.

  ```
  #generate keystore
  keytool -genkey -alias atomicbanana -keyalg RSA -sigalg SHA256withRSA -validity 3650 -keystore study_rsa.keystore -storetype JKS

  #export public cert
  keytool -export -alias atomicbanana -keystore study_rsa.keystore -rfc -file public.cert
  ```

## To package

  Run command below for package Jar file
  `chmod 755 mvnw`
  `./mvnw package`

## To execute

  Run command

  `java -jar target/studyrsaencryption-1.0-SNAPSHOT.jar`

## Usage

  ### genKeyPair
    
  It will generate RSA key pair and create 2 files `RSA/publicKey` and `RSA/privateKey`

  Java is able to generate RSA key pair but we ususally use `openssl` or `keytool`
  
  ### encrypt <publicKey path> <data to encrypt>

  It takes the publicKey path in `genKeyPair` and encrypt
    
  `java -jar target/studyrsaencryption-1.0-SNAPSHOT.jar encrypt RSA/publicKey "something to encrypt"`
  
  ### decrypt <privateKey path> <data to decrypt>

  It takes the privateKey path in `genKeyPair` and decrypt
  
  ### encryptByCert <data to encrypt>

  It will use `src/resources/public.cert` for encryption.
    
  ### decryptByCert <data to decrypt>

  It will use the private key inside `src/resources/study_rsa.keystore` for decryption.

## About this study

  There are two things I learned in this study.

  First one is the relationship of key and certificate
  
  how to generate/export them using `openssl` and `keytool`. 

  and their format.

  Second thing is using temp folder in JUnit Test.

  I wasn't sure if it is the right way to do but I ususally need to test create keys and file during my test.

  ### About Keys and Certificates

  In RSA public key is used for encryption and private is used for decryption.

  While keys do all the work, certificates are used for provide more information about the keys.

  For certificates, we usually refer to public key ceritficates. This ceritficate aims to distribute to public so that they can use it to encrypt message.

  The certificate will include public key, validity , org name and etc.

  To issue and sign a certificate, we need private key. If the private key is generated by ourself, the certificate we signed are called __self-signed certificate__.

  While you can have a trusted entity to sign certificate for you, it called __CA certificate__ (CA = certificate authority)
  
  ### Below are the key cert relationship summary

  - openssl -> privateKey

    `openssl genrsa -out private-key.pem 3072`

  - privateKey + Info = Cert (X509)

    `openssl req -new -x509 -key private-key.pem -out cert.pem -days 360`
  
  - privateKey -> publicKey

    `openssl rsa -in private-key.pem -pubout -out public-key.pem`
  
  - privateKey + Cert + password = p12 (PKCS12)

    `openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx`
  
  - Cert -> publicKey

    `openssl x509 -pubkey -in cert.pem -nocert -out export_public.pem`
  
  - p12 + password -> Cert (X509)

    `openssl pkcs12 -in keystore.p12  -nokeys -out cert.pem`

    The output `cert.pem` will include `Bag attribute`

    You may run below command to remove `Bag attribute`
    
    `openssl x509 -in cert.pem -out cert2.pem`
  
  - p12 + password -> privateKey

    `openssl pkcs12 -in keystore.p12  -nodes -nocerts -out key.pem`

    The output `key.pem` will include `Bag attribute`

    You may run below command to remove `Bag attribute`

    `openssl rsa -in key.pem -out key2.pem`
  
  - keytool + password + Info -> keystore (JKS)

    `keytool -genkey -alias atomicbanana -keyalg RSA -sigalg SHA256withRSA -validity 3650 -keystore study_rsa.keystore -storetype JKS`
  
  - keystore + password -> Cert (X509)

    `keytool -export -alias atomicbanana -keystore study_rsa.keystore -rfc -file public.cert`
  
  - keystore + keytool -> p12 (PKCS12)

    `keytool -importkeystore  -srckeystore keystore.jks -destkeystore keystore.p12 -deststoretype PKCS12 -srcalias atomicbanana `
  
  - p12 + keytool -> keystore (JKS)

    `keytool -importkeystore -srckeystore cert.pfx -srcstoretype pkcs12 -destkeystore opensslGen.keystore`

  ### other common commands

  - view info of p12
    
    `openssl pkcs12 -in example.p12 -info`

  - view info of keystore

    `keytool -list -v -keystore study_rsa.keystore`

  - change alias name in keystore

    `keytool -changealias -alias aliasToChange -destalias NewAliasName -keystore study_rsa.keystore`

## About format of key and certificate

  ### About format of public cert
  
  a public cert usually come with X509 format

  But it will be encoded and you will just see this if you `cat public.cert`

  ```
  -----BEGIN CERTIFICATE-----
MIIEhjCCAu6gAwIBAgIJAL+zMyUIgJ2nMA0GCSqGSIb3DQEBDAUAMHExEDAOBgNV
BAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25vd24x
EDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xFTATBgNVBAMTDGF0
b21pY2JhbmFuYTAeFw0yNTAyMDkwOTAyMTdaFw0zNTAyMDcwOTAyMTdaMHExEDAO
BgNVBAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25v
d24xEDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xFTATBgNVBAMT
DGF0b21pY2JhbmFuYTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALZ0
vt/1sJX2ZbmlNtmK7ckT6bWr7L8+JBqE6m2UgvTq6gNuywvqVWzL9EXFU3y81Oil
85TqCKTj/ADKQQLQ2xRsVTbl+AV6B0QDbq2o+9XiCO4seGt4NNfOszv3BstimTlY
oDVbIY7fhg2fveGejn7uzuoh6GZWCEe9J+q+Wyq0q+KNJDJe3nOgoNBuYvHPh8tv
gzjbFN21HDQBXuuBqTdlY4D3HVWQKEGcj/5hnhz+Iqcar1u6vu7KuKd/dqsXCUK7
eVTiyaP2rrEjhfGa03NI2/f9zENoLJSIjVzBUGun0JN17NQlBDaBemuyMcx9g6nw
ZuXsXGYag9pihDpuHpTd526Sp7JJ5H8QPmLYPbo1TnXtJ8a8Kk1I2FPsflxPdHTc
a22qwIsvWFqEzJ1UMJtdd7YCvZUM01vUPfNeyluYczsOGkHG5VXpFoc2BcddeClF
YmYBrQoobNBLyT2ZORl4LxI3jvWQwPbg1BSaeLdgxnoo7SRuWeWms8BfVgwmwwID
AQABoyEwHzAdBgNVHQ4EFgQULBsGHeI6/N8KQpMD/hKLTPuE/3IwDQYJKoZIhvcN
AQEMBQADggGBACoVTEUtYfYbsJMqia/EoBDOJQnfx5yd+DH8jTkWgJeAhXLkEFDs
YiP/GebK+Aw5Nu5LEgiwopOI7SgcBJjTTt2otrqwzssVaxjSENSmMs2pyOHms3CD
QOfQ6UPQlacNd8XcO3ItnWflJEnb/xXb4Q0/nny4hNuRub14bmCC693+EAE/95Wp
/6KvQ3WAuuWrWOe9d7PeITSioF0X3tz6L1XoaYxn08trBmjLafT2PzIMC4yIduEs
H64fAL8wOK4We8wATcBm3v5lRdpYPRs9V1z56Smfq4Kx9iFrxZMxES9iGpbnNZuX
dHWBLcyt2kIRCdiolMQoQ4AoUmpWtkReMf6BsYRHOvXc2MmTsNEMQpaAQQGa9rdq
hHBYzXYMbjFb+ft7zerMG7CvedJn5TOHHWeAULvzdUNcBuQ/bQOlusp+QgPJPhNT
ElUKGH2F1uus+PnJaUFHernd8ZKRF4n2B0tRKb7RpRtolbUbVUs1r8s9sy6JuytD
lI/gKABqx/TK6w==
-----END CERTIFICATE-----
  ```

To view the actual detail of the encoded public cert, you will need to run

  `openssl x509 -in public.cert -text`

  And you will see this
  
  ```
  
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            bf:b3:33:25:08:80:9d:a7
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C = Unknown, ST = Unknown, L = Unknown, O = Unknown, OU = Unknown, CN = atomicbanana
        Validity
            Not Before: Feb  9 09:02:17 2025 GMT
            Not After : Feb  7 09:02:17 2035 GMT
        Subject: C = Unknown, ST = Unknown, L = Unknown, O = Unknown, OU = Unknown, CN = atomicbanana
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (3072 bit)
                Modulus:
                    00:b6:74:be:df:f5:b0:95:f6:65:b9:a5:36:d9:8a:
                    ed:c9:13:e9:b5:ab:ec:bf:3e:24:1a:84:ea:6d:94:
                    82:f4:ea:ea:03:6e:cb:0b:ea:55:6c:cb:f4:45:c5:
                    53:7c:bc:d4:e8:a5:f3:94:ea:08:a4:e3:fc:00:ca:
                    41:02:d0:db:14:6c:55:36:e5:f8:05:7a:07:44:03:
                    6e:ad:a8:fb:d5:e2:08:ee:2c:78:6b:78:34:d7:ce:
                    b3:3b:f7:06:cb:62:99:39:58:a0:35:5b:21:8e:df:
                    86:0d:9f:bd:e1:9e:8e:7e:ee:ce:ea:21:e8:66:56:
                    08:47:bd:27:ea:be:5b:2a:b4:ab:e2:8d:24:32:5e:
                    de:73:a0:a0:d0:6e:62:f1:cf:87:cb:6f:83:38:db:
                    14:dd:b5:1c:34:01:5e:eb:81:a9:37:65:63:80:f7:
                    1d:55:90:28:41:9c:8f:fe:61:9e:1c:fe:22:a7:1a:
                    af:5b:ba:be:ee:ca:b8:a7:7f:76:ab:17:09:42:bb:
                    79:54:e2:c9:a3:f6:ae:b1:23:85:f1:9a:d3:73:48:
                    db:f7:fd:cc:43:68:2c:94:88:8d:5c:c1:50:6b:a7:
                    d0:93:75:ec:d4:25:04:36:81:7a:6b:b2:31:cc:7d:
                    83:a9:f0:66:e5:ec:5c:66:1a:83:da:62:84:3a:6e:
                    1e:94:dd:e7:6e:92:a7:b2:49:e4:7f:10:3e:62:d8:
                    3d:ba:35:4e:75:ed:27:c6:bc:2a:4d:48:d8:53:ec:
                    7e:5c:4f:74:74:dc:6b:6d:aa:c0:8b:2f:58:5a:84:
                    cc:9d:54:30:9b:5d:77:b6:02:bd:95:0c:d3:5b:d4:
                    3d:f3:5e:ca:5b:98:73:3b:0e:1a:41:c6:e5:55:e9:
                    16:87:36:05:c7:5d:78:29:45:62:66:01:ad:0a:28:
                    6c:d0:4b:c9:3d:99:39:19:78:2f:12:37:8e:f5:90:
                    c0:f6:e0:d4:14:9a:78:b7:60:c6:7a:28:ed:24:6e:
                    59:e5:a6:b3:c0:5f:56:0c:26:c3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                2C:1B:06:1D:E2:3A:FC:DF:0A:42:93:03:FE:12:8B:4C:FB:84:FF:72
    Signature Algorithm: sha384WithRSAEncryption
    Signature Value:
        2a:15:4c:45:2d:61:f6:1b:b0:93:2a:89:af:c4:a0:10:ce:25:
        09:df:c7:9c:9d:f8:31:fc:8d:39:16:80:97:80:85:72:e4:10:
        50:ec:62:23:ff:19:e6:ca:f8:0c:39:36:ee:4b:12:08:b0:a2:
        93:88:ed:28:1c:04:98:d3:4e:dd:a8:b6:ba:b0:ce:cb:15:6b:
        18:d2:10:d4:a6:32:cd:a9:c8:e1:e6:b3:70:83:40:e7:d0:e9:
        43:d0:95:a7:0d:77:c5:dc:3b:72:2d:9d:67:e5:24:49:db:ff:
        15:db:e1:0d:3f:9e:7c:b8:84:db:91:b9:bd:78:6e:60:82:eb:
        dd:fe:10:01:3f:f7:95:a9:ff:a2:af:43:75:80:ba:e5:ab:58:
        e7:bd:77:b3:de:21:34:a2:a0:5d:17:de:dc:fa:2f:55:e8:69:
        8c:67:d3:cb:6b:06:68:cb:69:f4:f6:3f:32:0c:0b:8c:88:76:
        e1:2c:1f:ae:1f:00:bf:30:38:ae:16:7b:cc:00:4d:c0:66:de:
        fe:65:45:da:58:3d:1b:3d:57:5c:f9:e9:29:9f:ab:82:b1:f6:
        21:6b:c5:93:31:11:2f:62:1a:96:e7:35:9b:97:74:75:81:2d:
        cc:ad:da:42:11:09:d8:a8:94:c4:28:43:80:28:52:6a:56:b6:
        44:5e:31:fe:81:b1:84:47:3a:f5:dc:d8:c9:93:b0:d1:0c:42:
        96:80:41:01:9a:f6:b7:6a:84:70:58:cd:76:0c:6e:31:5b:f9:
        fb:7b:cd:ea:cc:1b:b0:af:79:d2:67:e5:33:87:1d:67:80:50:
        bb:f3:75:43:5c:06:e4:3f:6d:03:a5:ba:ca:7e:42:03:c9:3e:
        13:53:12:55:0a:18:7d:85:d6:eb:ac:f8:f9:c9:69:41:47:7a:
        b9:dd:f1:92:91:17:89:f6:07:4b:51:29:be:d1:a5:1b:68:95:
        b5:1b:55:4b:35:af:cb:3d:b3:2e:89:bb:2b:43:94:8f:e0:28:
        00:6a:c7:f4:ca:eb
-----BEGIN CERTIFICATE-----
MIIEhjCCAu6gAwIBAgIJAL+zMyUIgJ2nMA0GCSqGSIb3DQEBDAUAMHExEDAOBgNV
BAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25vd24x
EDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xFTATBgNVBAMTDGF0
b21pY2JhbmFuYTAeFw0yNTAyMDkwOTAyMTdaFw0zNTAyMDcwOTAyMTdaMHExEDAO
BgNVBAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25v
d24xEDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xFTATBgNVBAMT
DGF0b21pY2JhbmFuYTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALZ0
vt/1sJX2ZbmlNtmK7ckT6bWr7L8+JBqE6m2UgvTq6gNuywvqVWzL9EXFU3y81Oil
85TqCKTj/ADKQQLQ2xRsVTbl+AV6B0QDbq2o+9XiCO4seGt4NNfOszv3BstimTlY
oDVbIY7fhg2fveGejn7uzuoh6GZWCEe9J+q+Wyq0q+KNJDJe3nOgoNBuYvHPh8tv
gzjbFN21HDQBXuuBqTdlY4D3HVWQKEGcj/5hnhz+Iqcar1u6vu7KuKd/dqsXCUK7
eVTiyaP2rrEjhfGa03NI2/f9zENoLJSIjVzBUGun0JN17NQlBDaBemuyMcx9g6nw
ZuXsXGYag9pihDpuHpTd526Sp7JJ5H8QPmLYPbo1TnXtJ8a8Kk1I2FPsflxPdHTc
a22qwIsvWFqEzJ1UMJtdd7YCvZUM01vUPfNeyluYczsOGkHG5VXpFoc2BcddeClF
YmYBrQoobNBLyT2ZORl4LxI3jvWQwPbg1BSaeLdgxnoo7SRuWeWms8BfVgwmwwID
AQABoyEwHzAdBgNVHQ4EFgQULBsGHeI6/N8KQpMD/hKLTPuE/3IwDQYJKoZIhvcN
AQEMBQADggGBACoVTEUtYfYbsJMqia/EoBDOJQnfx5yd+DH8jTkWgJeAhXLkEFDs
YiP/GebK+Aw5Nu5LEgiwopOI7SgcBJjTTt2otrqwzssVaxjSENSmMs2pyOHms3CD
QOfQ6UPQlacNd8XcO3ItnWflJEnb/xXb4Q0/nny4hNuRub14bmCC693+EAE/95Wp
/6KvQ3WAuuWrWOe9d7PeITSioF0X3tz6L1XoaYxn08trBmjLafT2PzIMC4yIduEs
H64fAL8wOK4We8wATcBm3v5lRdpYPRs9V1z56Smfq4Kx9iFrxZMxES9iGpbnNZuX
dHWBLcyt2kIRCdiolMQoQ4AoUmpWtkReMf6BsYRHOvXc2MmTsNEMQpaAQQGa9rdq
hHBYzXYMbjFb+ft7zerMG7CvedJn5TOHHWeAULvzdUNcBuQ/bQOlusp+QgPJPhNT
ElUKGH2F1uus+PnJaUFHernd8ZKRF4n2B0tRKb7RpRtolbUbVUs1r8s9sy6JuytD
lI/gKABqx/TK6w==
-----END CERTIFICATE-----
  ```

### about format of public key

You can `cat public-key.pem`.

It looks like this.

It was usually encoded with Base64. It will be a bunch of bytes if you decode it.

And we cannot read it anyway so we just look at the encoded format

```
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAroZM4TLuGjr65GjpqDeu
+EOJ3GGGrJ2BDsThTU249GbV1tGf4DsMW0XPI2diumfzQ9nbuWr1cgQ68yR6tsWL
Pop3dLqvMyb6TC8Gx4TYqxE55nt//l+yIapz0w0uRxVICZ6xS6s8t0WsABpa0eHi
6q375YTfUR50Iqur+XtU0t3WJR/DR8UIxZUENEPaGee917fOU81/e/2K7odYnbuC
5sNNv7H8x0z71dJvb2T45PB8C2/lkw7JlYf0ITEeRzv63AgbFA5+HDuVFQjqzH8X
fjSw1C95JJMYVXGsiEJSJLZXZ+/babcXtQdffd1gbaW/L1At5y+2SBXPlVmWp1cs
9DgyVx34Cik4zsPXvkEqSBXM/X4vtRY6SFFRzEONUeVWnyw2tOMMSavWFg26I35Q
VorEdfnpEQO2fqaL4jDgsQtrHjzp3fJ1QFaFQZFNQrgTNHTcc4Lu1/udkx9ZbUwe
cGfXy7y+875wLYzpuK9gqiUHAPU8NIcqsQzFLG/VGQL7AgMBAAE=
-----END PUBLIC KEY-----
```

### about format private key

The format is the same as public key. It was encoded in Base64.

You can  `cat private-key.pem` and get below

```
-----BEGIN PRIVATE KEY-----
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
fi6kea762JkyWYglD/W3S3I=
-----END PRIVATE KEY-----
```

### about .p12 and .keystore

.p12 and .keystore are both used for storing private key.

.p12 format is `PKCS12` and .keystore format is `JKS`

To view or perform any action with .p12 and .keystore, we need password.

We usually won't see a raw private key file such as above example `private-key.pem`.

We will see .p12 and .keystore.

.p12 and .keystore are interchangable using `keytool`

You can generate a raw private key and use `openssl` to make a .p12

or you can generate a .keystore using `keytool` it will then have a private key inside the keystore.

They looks like this
```
#for viewing keystore
keytool -list -v -keystore study_rsa.keystore

Enter keystore password:
Keystore type: JKS
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: atomicbanana
Creation date: Feb 10, 2025
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
Issuer: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
Serial number: 96d61bc41b1245b2
Valid from: Mon Feb 10 12:14:21 HKT 2025 until: Thu Feb 08 12:14:21 HKT 2035
Certificate fingerprints:
         SHA1: 78:26:40:7E:1D:CA:55:68:91:41:43:9F:21:99:2D:21:8B:54:B7:44
         SHA256: 15:4D:54:B1:95:96:86:3A:5A:AE:73:F4:B2:A2:41:C1:28:16:DF:73:46:A7:66:AE:80:72:9A:66:B8:A2:62:BE
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 83 42 FA B2 B1 04 1E C7   92 AD C4 A7 6E 95 CD EC  .B..........n...
0010: A3 D6 9C CF                                        ....
]
]



*******************************************
*******************************************



Warning:
The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using "keytool -importkeystore -srckeystore study_rsa.keystore -destkeystore study_rsa.keystore -deststoretype pkcs12".
anthony@LAPTOP-H26PJ91A:~/openssl_study$
```

```
#for viewing .p12 using keytool
keytool -list -v -keystore study_rsa.p12 -storetype PKCS12

Enter keystore password:
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: atomicbanana
Creation date: Feb 10, 2025
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
Issuer: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
Serial number: 96d61bc41b1245b2
Valid from: Mon Feb 10 12:14:21 HKT 2025 until: Thu Feb 08 12:14:21 HKT 2035
Certificate fingerprints:
         SHA1: 78:26:40:7E:1D:CA:55:68:91:41:43:9F:21:99:2D:21:8B:54:B7:44
         SHA256: 15:4D:54:B1:95:96:86:3A:5A:AE:73:F4:B2:A2:41:C1:28:16:DF:73:46:A7:66:AE:80:72:9A:66:B8:A2:62:BE
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 3072-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 83 42 FA B2 B1 04 1E C7   92 AD C4 A7 6E 95 CD EC  .B..........n...
0010: A3 D6 9C CF                                        ....
]
]



*******************************************
*******************************************


```


```
#for viewing p12 using openssl
openssl pkcs12 -in study_rsa.p12 -info

Enter Import Password:
MAC: sha256, Iteration 10000
MAC length: 32, salt length: 20
PKCS7 Data
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 10000, PRF hmacWithSHA256
Bag Attributes
    friendlyName: atomicbanana
    localKeyID: 54 69 6D 65 20 31 37 33 39 31 36 31 31 37 35 38 32 30
Key Attributes: <No Attributes>
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
-----END ENCRYPTED PRIVATE KEY-----
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 10000, PRF hmacWithSHA256
Certificate bag
Bag Attributes
    friendlyName: atomicbanana
    localKeyID: 54 69 6D 65 20 31 37 33 39 31 36 31 31 37 35 38 32 30
subject=C = Unknown, ST = Unknown, L = Unknown, O = Unknown, OU = Unknown, CN = Unknown
issuer=C = Unknown, ST = Unknown, L = Unknown, O = Unknown, OU = Unknown, CN = Unknown
-----BEGIN CERTIFICATE-----
MIIEfDCCAuSgAwIBAgIJAJbWG8QbEkWyMA0GCSqGSIb3DQEBCwUAMGwxEDAOBgNV
BAYTB1Vua25vd24xEDAOBgNVBAgTB1Vua25vd24xEDAOBgNVBAcTB1Vua25vd24x
EDAOBgNVBAoTB1Vua25vd24xEDAOBgNVBAsTB1Vua25vd24xEDAOBgNVBAMTB1Vu
a25vd24wHhcNMjUwMjEwMDQxNDIxWhcNMzUwMjA4MDQxNDIxWjBsMRAwDgYDVQQG
EwdVbmtub3duMRAwDgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAw
DgYDVQQKEwdVbmtub3duMRAwDgYDVQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtu
b3duMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAosOpBe/M/ByQsx4w
JOY4a1ortBCyvikWetLfOj07wUPZoD94yIvKFh6PzZBphWsVcjk4Umh1uEhx6pNW
T1w0KE3AlrmK+FFlxeohekDDR/LqaF7gjJf5/mfSjBtndi/AXC8jBU51Ft4sY9Pi
TJWytK6cddSTp9VNUpcpXvG2rJivv/GTuckSipEA/lmf6jYSTznmOp4B+fsrePM6
G4fvoLjsEVdxGY6IZxeevnd1X9YroNTc3aHqSBVXrxQ7MDQRNO/zJ8SfWGnK6TZT
SZmMshMctTpxsOBPlGw+aVMgtQ0ZkXaEzlrDDRCiJlHT5KNDuIAoHfs9AdhvYYqH
54tHGPSCxzkoEyyqEy5EmAch8cWsl5grZHPugo7iQyJr7eDhfQrnjDUx9sUD7vLo
X2TBSH+JwM28OUMBTFQuOIXPkoMHz8nQyXUwggal56DJYkbhoyZcubrN4wVmkGvE
F2DxcaPzRml2MNMgGKWq7gxj0pOpzN9zgxupOK7/40BRweu5AgMBAAGjITAfMB0G
A1UdDgQWBBSDQvqysQQex5KtxKdulc3so9aczzANBgkqhkiG9w0BAQsFAAOCAYEA
mytqbZmFfMlarQVuLnwbfkaTdZJAtemEXw/y4Obal/y9qcMgtR0knqeOQA02qATa
MKGU4J2Xo3stWnKhzbK9Le9Rxt7uhIT3dMwAFCp9FwArZrUHk2gaoeFBGagCBZQZ
bWZlahYMHq6G04+OkHb8sbktyL/z9WPDvUTdZ2McjfqKb5VgW5mc9epuXBgkqDeX
k+xuOohOPfoddQ3nt3uU2YyohGIQw1swvMbLpKTTiWgUMo0zSDNGLgigSMy6lnj9
vtX0z5tD4WA52squJC9C1jK9dMpkfsje0khU4EggVFTwdqQwBl1mm/ehYvOfTrAX
mtW9vsprEoRe0qQVB8pnZlNpb1ZHP3pNikrYZjNluwjEqHMNdBdZDvZJeMgDdBNI
QOFiCPtpstjwXZZYou6cXTu31cZxSRKJ9rcG+XmXBjbywU3r/ogYbuinOYZAr7X3
h6hgpgjdmgdPstDPdKm3uVw4EIH7o+axmNQdb7WeaARZeH9Erk6obS7/StLK2XSf
-----END CERTIFICATE-----
```

## About ECC and RSA

  There were some article said RSA may not be secure in future e.g. 2030

  Since RSA is commonly used and it may be cracked eventually.

  So there will be more and more people using another alogrithm call `ECC`.

  It is more complex and secure than `RSA`. Not sure if it is correct.

  But alogrithm changes time to time. Just need to be prepared.

## Reference
  
  Openssl command
  
  https://www.scottbrady.io/openssl/creating-rsa-keys-using-openssl
  
  Keys and Certificate 
  
  https://www.baeldung.com/cs/public-private-keys-vs-certificates
  
  About file type
  
  https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file
  
  Create temp folder for junit testing
  
  https://blogs.oracle.com/javamagazine/post/working-and-unit-testing-with-temporary-files-in-java
