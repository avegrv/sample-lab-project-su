package com.su.lab;

public class CipherTextWrapper {

    private byte[] cipherText;
    private byte[] initializationVector;


    public CipherTextWrapper(byte[] cipherText, byte[] initializationVector) {
        this.cipherText = cipherText;
        this.initializationVector = initializationVector;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }
}
