package com.example.dexhollowfixture;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.content.Intent;
import android.util.Log;

/** 验证输入 APK 已经声明自定义 AppComponentFactory 时，bootstrap 能保存原类名。 */
public final class FixtureComponentFactory extends AppComponentFactory {
    /**
     * 这个覆盖不能省略：真实 AndroidX CoreComponentFactory 会覆盖同一方法。若 Runtime
     * 把 Hook 安装在 InMemoryDexClassLoader 构造之后，这个方法可能已经绑定到 Hollow 桩，
     * 最终会向 Framework 返回 null Application。端到端测试必须覆盖这条最早启动路径。
     */
    @Override
    public Application instantiateApplication(ClassLoader classLoader, String className)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Log.i("DH13-FIXTURE", "FixtureComponentFactory.instantiateApplication");
        return super.instantiateApplication(classLoader, className);
    }

    @Override
    public Activity instantiateActivity(ClassLoader classLoader, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Log.i("DH13-FIXTURE", "FixtureComponentFactory.instantiateActivity");
        return super.instantiateActivity(classLoader, className, intent);
    }
}
