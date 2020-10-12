package com.su.lab;

import android.content.Context;

import javax.crypto.Cipher;

interface CryptographyManager {

    Cipher getInitializedCipherForEncryption(String keyName);

    Cipher getInitializedCipherForDecryption(String keyName, byte[] initializationVector);

    /**
     * The Cipher created with [getInitializedCipherForEncryption] is used here
     */
    CipherTextWrapper encryptData(String plaintext, Cipher cipher);

    /**
     * The Cipher created with [getInitializedCipherForDecryption] is used here
     */
    String decryptData(byte[] cipherText, Cipher cipher);

    void persistCipherTextWrapperToSharedPrefs(
            CipherTextWrapper ciphertextWrapper,
            Context context,
            String filename,
            int mode,
            String prefKey
    );

    CipherTextWrapper getCipherTextWrapperFromSharedPrefs(
            Context context,
            String filename,
            int mode,
            String prefKey
    );
}