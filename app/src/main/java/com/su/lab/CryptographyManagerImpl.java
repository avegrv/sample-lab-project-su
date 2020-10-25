package com.su.lab;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptographyManagerImpl implements CryptographyManager {

    private static final String TAG = "CryptographyManagerImpl";

    private static final String cypherInstance = "AES/CBC/PKCS7Padding";
    private static final String initializationVector = "8119745113154120";
    private static final String key = "fqIhyykbATjNQ2QdQlBOISNdjsaKdw==";


    @Override
    public CipherTextWrapper encryptData(String data) {
        String cipherText = null;

        try {
            cipherText = encrypt(key, data);
        } catch (Exception e) {
            Log.e(TAG, "encryptData", e);
        }
        return new CipherTextWrapper(cipherText, "");
    }

    @Override
    public String decryptData(CipherTextWrapper wrapper) {
        String cipherText = wrapper.getCipherText();
        String data = null;
        try {
            data = decrypt(key, cipherText);
        } catch (Exception e) {
            Log.e(TAG, "decryptData", e);
        }
        return data;
    }

    public static String encrypt(String key, String textToEncrypt) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(cypherInstance);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(initializationVector.getBytes()));
        byte[] encrypted = cipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String decrypt(String key, String textToDecrypt) throws Exception {
        byte[] encryted_bytes = Base64.decode(textToDecrypt, Base64.DEFAULT);
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(cypherInstance);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(initializationVector.getBytes()));
        byte[] decrypted = cipher.doFinal(encryted_bytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
