package com.su.lab;

public class CipherTextWrapper {

    private String cipherText;
    private String initializationVector;

    public CipherTextWrapper(String cipherText, String initializationVector) {
        this.cipherText = cipherText;
        this.initializationVector = initializationVector;
    }

    public String getCipherText() {
        return cipherText;
    }

    public String getInitializationVector() {
        return initializationVector;
    }
}
