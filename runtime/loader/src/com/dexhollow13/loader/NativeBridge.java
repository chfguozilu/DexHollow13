package com.dexhollow13.loader;

import java.nio.ByteBuffer;

/** Loader DEX 与 libdexhollow13_shell.so 之间唯一的 JNI 边界。 */
final class NativeBridge {
    static final int RESOURCE_BOOTSTRAP = 1;
    static final int RESOURCE_HOLLOW_DEX = 2;

    static {
        // System.loadLibrary 使用当前 Loader DEX 所属 PathClassLoader 的 nativeLibraryPath，
        // 从 APK 的 lib/<abi>/ 找到项目专属的 libdexhollow13_shell.so。专属名称避免与原
        // APK 自己的壳或 Native SDK 冲突；该 Loader SO 不会执行或恢复任何业务 DEX。
        System.loadLibrary("dexhollow13_shell");
    }

    private NativeBridge() {}

    static void initialize(ByteBuffer[] hollowDexBuffers, ByteBuffer[] payloadBuffers) {
        nativeInitialize(hollowDexBuffers, payloadBuffers);
    }

    /** 解密 bootstrap 这类小资源；返回前 Native 已验证 XChaCha20-Poly1305 tag。 */
    static byte[] decryptResource(byte[] sealed, int kind, int ordinal) {
        return nativeDecryptResource(sealed, kind, ordinal);
    }

    /**
     * 把较大的 Hollow DEX 从密文缓存直接解到应用私有临时文件。
     *
     * Native 使用 input/output mmap，不会为整个 DEX 创建 Java byte[]；调用者映射成功后会
     * 立即 unlink 明文临时文件，只保留当前进程持有的只读映射。
     */
    static void decryptResourceFile(String inputPath, String outputPath, int kind, int ordinal) {
        nativeDecryptResourceFile(inputPath, outputPath, kind, ordinal);
    }

    /**
     * 返回已经在 ClassLinker::LoadMethod 中改为 Shadow CodeItem 的 ArtMethod 数量。
     *
     * 这个数值只用于启动链诊断：创建原 AppComponentFactory 前后比较它，就能区分
     * “类根本没有经过 Hook”与“已经绑定，但执行入口仍错误地运行 Hollow 桩”。
     */
    static long boundMethodCount() {
        return nativeBoundMethodCount();
    }

    /**
     * Native 层必须在第一个原应用类被定义前完成 Payload 校验和 ART hook 安装。
     * 失败时它直接抛出 IllegalStateException，不能退化为执行 Hollow 返回桩。
     */
    private static native void nativeInitialize(
        ByteBuffer[] hollowDexBuffers, ByteBuffer[] payloadBuffers);

    private static native byte[] nativeDecryptResource(byte[] sealed, int kind, int ordinal);

    private static native void nativeDecryptResourceFile(
        String inputPath, String outputPath, int kind, int ordinal);

    private static native long nativeBoundMethodCount();
}
