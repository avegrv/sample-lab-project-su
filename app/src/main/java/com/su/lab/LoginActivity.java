package com.su.lab;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.Nullable;

public class LoginActivity extends Activity {

    private final String CIPHER_KEY = "pin_code";

    private final CryptographyManager cryptographyManager = new CryptographyManagerImpl();
    private final CipherTextWrapperStorage storage = new CipherTextWrapperStorageImpl();

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        Button button = findViewById(R.id.button);

        boolean isPinExist = storage.isCipherTextWrapperExist(this);
        button.setText(isPinExist ? R.string.login_button_enter : R.string.login_button_create_pin);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onNextClicked();
            }
        });
    }

    private void onNextClicked() {
        if (storage.isCipherTextWrapperExist(this)) {
            checkPin();
        } else {
            createPin();
        }
    }

    private void createPin() {
        EditText editTextTextPassword = findViewById(R.id.editTextTextPassword);
        String pin = editTextTextPassword.getText().toString();

        CipherTextWrapper wrapper = cryptographyManager.encryptData(pin, CIPHER_KEY);
        storage.persistCipherTextWrapper(this, wrapper);

        Toast.makeText(this, "Pin created", Toast.LENGTH_SHORT).show();

        editTextTextPassword.setText(null);
        Button button = findViewById(R.id.button);
        button.setText(R.string.login_button_enter);
    }

    private void checkPin() {
        EditText editTextTextPassword = findViewById(R.id.editTextTextPassword);
        String password = editTextTextPassword.getText().toString();

        CipherTextWrapper cipherTextWrapper = storage.getCipherTextWrapper(this);
        if (cipherTextWrapper == null) {
            Toast.makeText(this, "Setup pin first", Toast.LENGTH_SHORT).show();
            return;
        }

        String decrypted = cryptographyManager.decryptData(cipherTextWrapper, CIPHER_KEY);
        boolean isSamePassword = decrypted.equals(password);
        if (isSamePassword) {
            /*
             *  TODO #2 Открыть MainActivity через Intent
             *   http://developer.alexanderklimov.ru/android/theory/intent.php
             */
            Intent intent = new Intent(this, MainActivity.class);
            startActivity(intent);
        } else {
            Toast.makeText(this, "Wrong password", Toast.LENGTH_SHORT).show();
        }
    }
}
