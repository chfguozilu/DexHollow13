package com.example.dexhollowfixture;

/**
 * 构建脚本会把这个类单独放进 classes2.dex。
 * MainActivity 对它的直接调用用于证明多个 DEX 共用一个 InMemoryDexClassLoader，且
 * dex signature + method_idx 能把第二份 Payload 精确匹配到第二个 ART DexFile。
 */
public final class SecondarySecret {
    public static String token() {
        return "dex2-ok";
    }
}
