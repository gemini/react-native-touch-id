package com.rnfingerprint;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.crypto.Cipher;

public class FingerprintAuthModule extends ReactContextBaseJavaModule implements LifecycleEventListener {

    private static final String FRAGMENT_TAG = "fingerprint_dialog";
    private static final String SAVED_FINGERPRINT_IDS = "SAVED_FINGERPRINT_IDS";

    private KeyguardManager keyguardManager;
    private boolean isAppActive;

    public static boolean inProgress = false;

    public FingerprintAuthModule(final ReactApplicationContext reactContext) {
        super(reactContext);

        reactContext.addLifecycleEventListener(this);
    }

    private KeyguardManager getKeyguardManager() {
        if (keyguardManager != null) {
            return keyguardManager;
        }
        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return null;
        }

        keyguardManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);

        return keyguardManager;
    }

    @Override
    public String getName() {
        return "FingerprintAuth";
    }

    @ReactMethod
    public void checkIfKeyIsValid(final Callback validCallback) {
        validCallback.invoke(fingerPrintsAreValid());
    }

    private boolean fingerPrintsAreValid() {
        HashSet<String> currentFingerPrints = getFingerprintIds(getReactApplicationContext());
        HashSet<String> savedFingerPrints = getSavedFingerPrints();
        return currentFingerPrints.equals(savedFingerPrints);
    }

    @ReactMethod
    public void renewKey() {
        HashSet<String> currentFingerPrints = getFingerprintIds(getReactApplicationContext());
        SharedPreferences.Editor editor = getReactApplicationContext().getSharedPreferences(FRAGMENT_TAG, Context.MODE_PRIVATE).edit();
        editor.putStringSet(SAVED_FINGERPRINT_IDS, currentFingerPrints);
        editor.apply();

    }

    public HashSet<String> getSavedFingerPrints() {

        return new HashSet<String>(getReactApplicationContext().getSharedPreferences(FRAGMENT_TAG, Context.MODE_PRIVATE).getStringSet(SAVED_FINGERPRINT_IDS, new HashSet<String>()));
    }

    private HashSet<String> getFingerprintIds(Context context)
    {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {

            try {
                FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
                Method method = null;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                    method = FingerprintManager.class.getDeclaredMethod("getEnrolledFingerprints");
                }
                Object obj = method.invoke(fingerprintManager);

                if (obj != null) {
                    HashSet<String> fingerprintIds = new HashSet<>();
                    Class<?> clazz = Class.forName("android.hardware.fingerprint.Fingerprint");
                    Method getFingerId = clazz.getDeclaredMethod("getFingerId");

                    for (int i = 0; i < ((List) obj).size(); i++) {
                        Object item = ((List) obj).get(i);
                        if (item != null) {
                            fingerprintIds.add("" + getFingerId.invoke(item));
                        }
                    }
                    return fingerprintIds;
                }
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        return new HashSet<String>();
    }

    @ReactMethod
    public void isSupported(final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return;
        }

        int result = isFingerprintAuthAvailable();
        if (result == FingerprintAuthConstants.IS_SUPPORTED) {
            reactSuccessCallback.invoke("Is supported.");
        } else {
            reactErrorCallback.invoke("Not supported.", result);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @ReactMethod
    public void authenticate(final String reason, final ReadableMap authConfig, final Callback reactErrorCallback, final Callback reactSuccessCallback) {
        final Activity activity = getCurrentActivity();
        if (inProgress || !isAppActive || activity == null) {
            return;
        }
        inProgress = true;

        int availableResult = isFingerprintAuthAvailable();
        if (availableResult != FingerprintAuthConstants.IS_SUPPORTED) {
            inProgress = false;
            reactErrorCallback.invoke("Not supported", availableResult);
            return;
        }

        /* FINGERPRINT ACTIVITY RELATED STUFF */
        final Cipher cipher = new FingerprintCipher().getCipher();
        if (cipher == null) {
            inProgress = false;
            reactErrorCallback.invoke("Not supported", FingerprintAuthConstants.NOT_AVAILABLE);
            return;
        }

        if (!fingerPrintsAreValid()) {
            inProgress = false;
            reactErrorCallback.invoke("New Fingerprint Added", FingerprintAuthConstants.NEW_FINGERPRINT_ADDED);
            return;
        }

        // We should call it only when we absolutely sure that API >= 23.
        // Otherwise we will get the crash on older versions.
        // TODO: migrate to FingerprintManagerCompat
        final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

        final DialogResultHandler drh = new DialogResultHandler(reactErrorCallback, reactSuccessCallback);

        final FingerprintDialog fingerprintDialog = new FingerprintDialog();
        fingerprintDialog.setCryptoObject(cryptoObject);
        fingerprintDialog.setReasonForAuthentication(reason);
        fingerprintDialog.setAuthConfig(authConfig);
        fingerprintDialog.setDialogCallback(drh);

        if (!isAppActive) {
            inProgress = false;
            return;
        }

        fingerprintDialog.show(activity.getFragmentManager(), FRAGMENT_TAG);
    }

    private int isFingerprintAuthAvailable() {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return FingerprintAuthConstants.NOT_SUPPORTED;
        }

        final Activity activity = getCurrentActivity();
        if (activity == null) {
            return FingerprintAuthConstants.NOT_AVAILABLE; // we can't do the check
        }

        final KeyguardManager keyguardManager = getKeyguardManager();

        // We should call it only when we absolutely sure that API >= 23.
        // Otherwise we will get the crash on older versions.
        // TODO: migrate to FingerprintManagerCompat
        final FingerprintManager fingerprintManager = (FingerprintManager) activity.getSystemService(Context.FINGERPRINT_SERVICE);

        if (fingerprintManager == null || !fingerprintManager.isHardwareDetected()) {
            return FingerprintAuthConstants.NOT_PRESENT;
        }

        if (keyguardManager == null || !keyguardManager.isKeyguardSecure()) {
            return FingerprintAuthConstants.NOT_AVAILABLE;
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            return FingerprintAuthConstants.NOT_ENROLLED;
        }
        return FingerprintAuthConstants.IS_SUPPORTED;
    }

    @Override
    public void onHostResume() {
        isAppActive = true;
    }

    @Override
    public void onHostPause() {
        isAppActive = false;
    }

    @Override
    public void onHostDestroy() {
        isAppActive = false;
    }
}
