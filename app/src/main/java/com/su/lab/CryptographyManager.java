package com.su.lab;

interface CryptographyManager {

    CipherTextWrapper encryptData(String data, String keyName);

    String decryptData(CipherTextWrapper wrapper, String keyName);
}