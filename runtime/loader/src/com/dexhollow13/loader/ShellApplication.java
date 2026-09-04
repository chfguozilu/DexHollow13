package com.dexhollow13.loader;

import android.app.Application;

/**
 * Manifest 中稳定存在的壳 Application 名称。
 *
 * Android 13 正常路径会由 ShellComponentFactory.instantiateApplication() 返回原 Application，
 * 因而这个类不会成为最终 Application 对象。保留实体类是为了让 PackageManager 和不调用
 * AppComponentFactory 的静态工具仍能解析 Manifest，同时也给异常路径提供明确错误。
 */
public final class ShellApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        throw new IllegalStateException(
            "ShellComponentFactory 未返回原 Application，DexHollow13 启动链不完整");
    }
}
