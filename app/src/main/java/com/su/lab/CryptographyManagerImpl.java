package com.su.lab;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import androidx.annotation.Nullable;

public class CryptographyManagerImpl implements CryptographyManager {

    private static final String TAG = "CryptographyManagerImpl";

    private static final int KEY_SIZE = 256;
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES;
    private static final String ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM;
    private static final String ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE;

    @Override
    public Cipher getInitializedCipherForEncryption(String keyName) {
        Cipher cipher = getCipher();
        try {
            SecretKey secretKey = getOrCreateSecretKey(keyName);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (Exception e) {
            Log.e(TAG, "getInitializedCipherForEncryption", e);
        }
        return cipher;
    }

    @Override
    public Cipher getInitializedCipherForDecryption(String keyName, byte[] initializationVector) {
        Cipher cipher = getCipher();
        try {
            SecretKey secretKey = getOrCreateSecretKey(keyName);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
        } catch (Exception e) {
            Log.e(TAG, "getInitializedCipherForEncryption", e);
        }
        return cipher;
    }

    @Override
    public CipherTextWrapper encryptData(String plaintext, Cipher cipher) {
        byte[] cipherText = null;
        try {
            cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.ISO_8859_1));
        } catch (Exception e) {
            Log.e(TAG, "encryptData", e);
        }
        return new CipherTextWrapper(cipherText, cipher.getIV());
    }

    @Override
    public String decryptData(byte[] cipherText, Cipher cipher) {
        byte[] plaintext = null;
        try {
            plaintext = cipher.doFinal(cipherText);
        } catch (Exception e) {
            Log.e(TAG, "encryptData", e);
        }
        return new String(plaintext, StandardCharsets.ISO_8859_1);
    }

    @Override
    public void persistCipherTextWrapperToSharedPrefs(
            CipherTextWrapper cipherTextWrapper,
            Context context,
            String filename,
            int mode,
            String prefKey
    ) {
        context.getSharedPreferences(filename, mode).edit()
                .putString(prefKey, new String(cipherTextWrapper.getCipherText(), StandardCharsets.ISO_8859_1))
                .putString(prefKey + "_iv", new String(cipherTextWrapper.getInitializationVector(), StandardCharsets.ISO_8859_1))
                .apply();
    }

    @Nullable
    @Override
    public CipherTextWrapper getCipherTextWrapperFromSharedPrefs(
            Context context,
            String filename,
            int mode,
            String prefKey
    ) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(filename, mode);
        String cipherText = sharedPreferences.getString(prefKey, null);
        String initializationVector = sharedPreferences.getString(prefKey + "_iv", null);
        if (cipherText == null || initializationVector == null) {
            return null;
        }
        return new CipherTextWrapper(
                cipherText.getBytes(StandardCharsets.ISO_8859_1),
                initializationVector.getBytes(StandardCharsets.ISO_8859_1)
        );
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
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        } catch (KeyStoreException e) {
            Log.e(TAG, "KeyStoreException", e);
        }
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
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
        );
        keyGenerator.init(keyGenParams);
        return keyGenerator.generateKey();
    }

    private Cipher getCipher() {
        final String transformation = ENCRYPTION_ALGORITHM
                + "/" + ENCRYPTION_BLOCK_MODE
                + "/" + ENCRYPTION_PADDING;
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "getCipher:NoSuchAlgorithmException", e);
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "getCipher:NoSuchPaddingException", e);
        }
        return cipher;
    }
}
