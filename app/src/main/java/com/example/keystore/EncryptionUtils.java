package com.example.keystore;

import android.content.Context;
import android.os.Build;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import timber.log.Timber;

public class EncryptionUtils {

  public static String encrypt(Context context, String token) {
    SecurityKey securityKey = getSecurityKey(context);
    return securityKey != null ? securityKey.encrypt(token) : null;
  }

  public static String decrypt(Context context, String token) {
    SecurityKey securityKey = getSecurityKey(context);
    return securityKey != null ? securityKey.decrypt(token) : null;
  }

  private static SecurityKey getSecurityKey(Context context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      return EncryptionKeyGenerator.generateSecretKey(getKeyStore());
    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
      return EncryptionKeyGenerator.generateKeyPairPreM(context, getKeyStore());
    } else {
      return EncryptionKeyGenerator.generateSecretKeyPre18(context);
    }
  }

  private static KeyStore getKeyStore() {
    KeyStore keyStore = null;
    try {
      keyStore = KeyStore.getInstance(EncryptionKeyGenerator.ANDROID_KEY_STORE);
      keyStore.load(null);
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
      Timber.e(e);
    }
    return keyStore;
  }

  public static void clear() {
    KeyStore keyStore = getKeyStore();
    try {
      if (keyStore.containsAlias(EncryptionKeyGenerator.KEY_ALIAS)) {
        keyStore.deleteEntry(EncryptionKeyGenerator.KEY_ALIAS);
      }
    } catch (KeyStoreException e) {
      Timber.e(e);
    }
  }
}
