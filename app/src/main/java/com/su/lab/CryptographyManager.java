package com.su.lab;

import android.content.Context;

interface CryptographyManager {

    CipherTextWrapper encryptData(Context context, String data, String keyName);

    String decryptData(Context context, CipherTextWrapper wrapper, String keyName);
}