package com.example.keystore;

import android.os.Build;
import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import timber.log.Timber;

class SecurityKey {
  private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
  private static final String AES_MODE_FOR_POST_API_23 = "AES/GCM/NoPadding";
  private static final String AES_MODE_FOR_PRE_API_18 = "AES/CBC/PKCS5Padding";

  private SecretKey secretKey;
  private KeyPair keyPair;

  SecurityKey(SecretKey secretKey) {
    this.secretKey = secretKey;
  }

  SecurityKey(KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  String encrypt(String token) {
    if (token == null) return null;

    try {
      Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);

      byte[] encrypted = cipher.doFinal(token.getBytes());
      return Base64.encodeToString(encrypted, Base64.URL_SAFE);
    } catch (GeneralSecurityException e) {
      Timber.e(e);
    }
    //Unable to encrypt Token
    return null;
  }

  String decrypt(String encryptedToken) {
    if (encryptedToken == null) return null;

    try {
      Cipher cipher = getCipher(Cipher.DECRYPT_MODE);

      byte[] decoded = Base64.decode(encryptedToken, Base64.URL_SAFE);
      byte[] original = cipher.doFinal(decoded);
      return new String(original);
    } catch (GeneralSecurityException e) {
      Timber.e(e);
    }
    //Unable to decrypt encrypted Token
    return null;
  }

  private Cipher getCipher(int mode) throws GeneralSecurityException {
    Cipher cipher;

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      cipher = Cipher.getInstance(AES_MODE_FOR_POST_API_23);
      cipher.init(mode, secretKey, new GCMParameterSpec(128, AES_MODE_FOR_POST_API_23.getBytes(), 0, 12));
    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
      cipher = Cipher.getInstance(RSA_MODE);
      cipher.init(mode, mode == Cipher.DECRYPT_MODE ? keyPair.getPublic() : keyPair.getPrivate());
    } else {
      cipher = Cipher.getInstance(AES_MODE_FOR_PRE_API_18);
      cipher.init(mode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));
    }
    return cipher;
  }
}