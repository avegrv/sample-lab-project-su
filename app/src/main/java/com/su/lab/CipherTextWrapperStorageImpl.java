package com.su.lab;

import android.content.Context;
import android.content.SharedPreferences;

public class CipherTextWrapperStorageImpl implements CipherTextWrapperStorage {

    private static final String SHARED_PREF_FILE_NAME = "login_prefs";
    private static final String PIN_KEY = "pin";
    private static final String PIN_IV_KEY = "pin_iv";

    @Override
    public void persistCipherTextWrapper(Context context, CipherTextWrapper wrapper) {
        /*
         *  TODO #1 Реализовать сохрание шифр. текста cipherText и вектора инициализации initializationVector
         *    из CipherTextWrapper в SharedPreferences, используя ключи PIN_KEY и PIN_IV_KEY
         *  https://www.fandroid.info/sharedpreferences-sohranenie-dannyh-v-postoyannoe-hranilishhe-android/
         *
         */
        SharedPreferences settings = context.getSharedPreferences(SHARED_PREF_FILE_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(PIN_KEY, wrapper.getCipherText());
        editor.putString(PIN_IV_KEY, wrapper.getInitializationVector());
        editor.commit();
    }

    @Override
    public CipherTextWrapper getCipherTextWrapper(Context context) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(SHARED_PREF_FILE_NAME, Context.MODE_PRIVATE);
        String cipherText = sharedPreferences.getString(PIN_KEY, null);
        String initializationVector = sharedPreferences.getString(PIN_IV_KEY, null);
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
