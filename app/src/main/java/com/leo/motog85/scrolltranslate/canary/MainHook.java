package com.leo.motog85.scrolltranslate.canary;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.MethodDataList;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public final class MainHook implements IXposedHookLoadPackage {
    private static final String TARGET_PKG = "com.google.android.googlequicksearchbox";
    private static final String TARGET_PROCESS = "com.google.android.googlequicksearchbox:googleapp";
    private static final long TARGET_VERSION = 301805186L;
    private static final String MP_EXTRA = "android.media.projection.extra.EXTRA_MEDIA_PROJECTION";
    private static volatile boolean ran;

    private static void log(String s) {
        XposedBridge.log("MotoG85P74: " + s);
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) return;
        if (!TARGET_PROCESS.equals(lpparam.processName)) return;
        log("P7.4-LOAD-00 GOOGLEAPP_MATCH process=" + lpparam.processName);

        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (ran) return;
                ran = true;
                Context context = (Context) param.args[0];
                try {
                    PackageInfo pi = context.getPackageManager().getPackageInfo(TARGET_PKG, 0);
                    long vc = pi.getLongVersionCode();
                    String vn = pi.versionName;
                    if (vc != TARGET_VERSION) {
                        log("P7.4-90 FAIL_OPEN phase=version versionCode=" + vc + " versionName=" + vn);
                        return;
                    }
                    log("P7.4-LOAD-01 VERSION_OK versionCode=" + vc + " versionName=" + vn);
                    enumerate(context);
                } catch (Throwable t) {
                    log("P7.4-90 FAIL_OPEN phase=attach throwable=" + t.getClass().getName() + ":" + t.getMessage());
                }
            }
        });
    }

    private static void enumerate(Context context) {
        DexKitBridge bridge = null;
        try {
            try {
                System.loadLibrary("dexkit");
                log("P7.4-LOAD-02 DEXKIT_JNI_OK");
            } catch (Throwable t) {
                log("P7.4-90 FAIL_OPEN phase=dexkit_load throwable=" + t.getClass().getName() + ":" + t.getMessage());
                return;
            }

            String apk = context.getApplicationInfo().sourceDir;
            bridge = DexKitBridge.create(apk);
            MethodDataList methods = bridge.findMethod(
                    FindMethod.create().matcher(
                            MethodMatcher.create().usingStrings(MP_EXTRA)
                    )
            );
            log("P7.4-MAP-00 CONSUMER_COUNT count=" + methods.size());
            int i = 0;
            for (MethodData md : methods) {
                log("P7.4-MAP-10 MP_CONSUMER_FOUND index=" + (i++) + " method=" + md);
            }
            if (methods.size() == 0) {
                log("P7.4-90 FAIL_OPEN phase=enumeration consumerCount=0");
            } else {
                log("P7.4-MAP-20 ENUMERATION_COMPLETE consumerCount=" + methods.size());
            }
        } catch (Throwable t) {
            log("P7.4-90 FAIL_OPEN phase=dexkit throwable=" + t.getClass().getName() + ":" + t.getMessage());
        } finally {
            if (bridge != null) {
                try { bridge.close(); } catch (Throwable ignored) {}
            }
        }
    }
}
