package com.su.lab;

import android.content.Context;
import android.content.SharedPreferences;

public class CipherTextWrapperStorageImpl implements CipherTextWrapperStorage {

    private static final String SHARED_PREF_FILE_NAME = "login_prefs";
    private static final String PIN_KEY = "pin";
    private static final String PIN_IV_KEY = "pin_iv";

    @Override
    public void persistCipherTextWrapper(Context context, CipherTextWrapper wrapper) {
        SharedPreferences settings = context.getSharedPreferences(SHARED_PREF_FILE_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(PIN_KEY, wrapper.getCipherText());
        editor.putString(PIN_IV_KEY, wrapper.getInitializationVector());
        editor.apply();
    }

    @Override
    public CipherTextWrapper getCipherTextWrapper(Context context) {
        String cipherText = null;
        String initializationVector = null;
        SharedPreferences settings = context.getSharedPreferences(SHARED_PREF_FILE_NAME, Context.MODE_PRIVATE);
        cipherText = settings.getString(PIN_KEY, null);
        initializationVector = settings.getString(PIN_IV_KEY, null);
        if (cipherText == null || initializationVector == null) {
            return null;
        }
        return new CipherTextWrapper(cipherText, initializationVector);
    }

    @Override
    public boolean isCipherTextWrapperExist(Context context) {
        return this.getCipherTextWrapper(context) != null;
    }
}
