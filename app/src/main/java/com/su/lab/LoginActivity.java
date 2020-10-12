package com.su.lab;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;

import androidx.annotation.Nullable;

public class LoginActivity extends Activity {

    private final String SHARED_PREF = "login_prefs";
    private final String PIN_KEY = "key";

    private final String CIPHER_KEY = "CIPHER_KEY";

    private final CryptographyManager cryptographyManager = new CryptographyManagerImpl();

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        Button button = findViewById(R.id.button);

        boolean isPinExist = isPinExist();
        button.setText(isPinExist ? R.string.login_button_enter : R.string.login_button_create_pin);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onNextClicked();
            }
        });
    }

    private void onNextClicked() {
        if (isPinExist()) {
            checkPin();
        } else {
            createPin();
        }
    }

    private void createPin() {
        EditText editTextTextPassword = findViewById(R.id.editTextTextPassword);
        String pin = editTextTextPassword.getText().toString();

        Cipher cipher = cryptographyManager.getInitializedCipherForEncryption(CIPHER_KEY);
        CipherTextWrapper encrypted = cryptographyManager.encryptData(pin, cipher);
        cryptographyManager.persistCipherTextWrapperToSharedPrefs(encrypted, this,
                SHARED_PREF, Context.MODE_PRIVATE, PIN_KEY);
        Toast.makeText(this, "Pin created", Toast.LENGTH_SHORT).show();
        editTextTextPassword.setText(null);
        Button button = findViewById(R.id.button);
        button.setText(R.string.login_button_enter);
    }

    private void checkPin() {
        EditText editTextTextPassword = findViewById(R.id.editTextTextPassword);
        String password = editTextTextPassword.getText().toString();

        CipherTextWrapper cipherTextWrapper = cryptographyManager.getCipherTextWrapperFromSharedPrefs(
                this, SHARED_PREF, Context.MODE_PRIVATE, PIN_KEY);
        if (cipherTextWrapper == null) {
            Toast.makeText(this, "Setup pin first", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] cipherText = cipherTextWrapper.getCipherText();
        byte[] iv = cipherTextWrapper.getInitializationVector();
        Cipher cipher = cryptographyManager.getInitializedCipherForDecryption(CIPHER_KEY, iv);
        String decrypted = cryptographyManager.decryptData(cipherText, cipher);
        boolean isSame = decrypted.equals(password);
        if (isSame) {
            Intent intent = new Intent(this, MainActivity.class);
            startActivity(intent);
        } else {
            Toast.makeText(this, "Wrong password", Toast.LENGTH_SHORT).show();
        }
    }

    private boolean isPinExist() {
        return cryptographyManager.getCipherTextWrapperFromSharedPrefs(
                this, SHARED_PREF, Context.MODE_PRIVATE, PIN_KEY) != null;
    }
}
