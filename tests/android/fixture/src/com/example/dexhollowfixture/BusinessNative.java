package com.example.dexhollowfixture;

/** 模拟原 APK 自带的业务 Native 库，用于验证业务 ClassLoader 的 SO 搜索路径。 */
final class BusinessNative {
    static {
        // 该类最终由 InMemoryDexClassLoader 定义，因此这里会调用它自己的 findLibrary()。
        // Loader 若只设置 Java parent、却没有设置 librarySearchPath，此处会直接崩溃。
        System.loadLibrary("fixturebusiness");
    }

    private BusinessNative() {}

    static native int plusSeven(int value);
}
