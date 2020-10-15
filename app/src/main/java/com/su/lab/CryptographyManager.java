package com.su.lab;

interface CryptographyManager {

    CipherTextWrapper encryptData(String data);

    String decryptData(CipherTextWrapper wrapper);
}