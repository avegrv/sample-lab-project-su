package com.su.lab;

import android.content.Context;

interface CipherTextWrapperStorage {

    void persistCipherTextWrapper(Context context, CipherTextWrapper wrapper);

    CipherTextWrapper getCipherTextWrapper(Context context);

    boolean isCipherTextWrapperExist(Context context);
}
