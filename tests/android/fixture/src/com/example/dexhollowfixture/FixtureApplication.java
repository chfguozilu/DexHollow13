package com.example.dexhollowfixture;

import android.app.Application;
import android.util.Log;

/** 用来验证壳是否真正恢复并调用了原 Application，而不是只让 Activity 偶然启动。 */
public final class FixtureApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i("DH13-FIXTURE", "FixtureApplication.onCreate");
    }
}
