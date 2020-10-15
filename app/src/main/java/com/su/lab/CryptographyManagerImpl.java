package com.su.lab;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptographyManagerImpl implements CryptographyManager {

    private static final String TAG = "CryptographyManagerImpl";

    private static final int KEY_SIZE = 256;
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM;
    private static final String ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE;

    @Override
    public CipherTextWrapper encryptData(String data, String keyName) {
        try {
            return new CipherTextWrapper(Base64.encodeToString(SHA1(data).getBytes(StandardCharsets.UTF_8), Base64.DEFAULT), "");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                }
                else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while(two_halfs++ < 1);
        }
        return buf.toString();
    }


    public static String SHA1(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] sha1hash;
        md.update(text.getBytes(StandardCharsets.UTF_8), 0, text.length());
        sha1hash = md.digest();
        return convertToHex(sha1hash);
    }

    @Override
    public String decryptData(CipherTextWrapper wrapper, String keyName) {
        return new String(Base64.decode(wrapper.getCipherText(), Base64.DEFAULT), StandardCharsets.UTF_8);
    }

    private SecretKey getOrCreateSecretKey(String keyName) throws
            CertificateException,
            NoSuchAlgorithmException,
            IOException,
            KeyStoreException,
            UnrecoverableKeyException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
        // If Secretkey was previously created for that keyName, then grab and return it.
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        assert keyStore != null;
        keyStore.load(null); // Keystore must be loaded before it can be accessed
        Key key = keyStore.getKey(keyName, null);
        if (key != null) {
            return (SecretKey) key;
        }

        // if you reach here, then a new SecretKey must be generated for that keyName
        KeyGenParameterSpec keyGenParams = new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
                .setBlockModes(ENCRYPTION_BLOCK_MODE)
                .setEncryptionPaddings(ENCRYPTION_PADDING)
                .setKeySize(KEY_SIZE)
                .setUserAuthenticationRequired(false)
                .build();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                ENCRYPTION_ALGORITHM,
                ANDROID_KEYSTORE
        );
        keyGenerator.init(keyGenParams);
        return keyGenerator.generateKey();
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        final String transformation = ENCRYPTION_ALGORITHM
                + "/" + ENCRYPTION_BLOCK_MODE
                + "/" + ENCRYPTION_PADDING;
        return Cipher.getInstance(transformation);
    }
}
