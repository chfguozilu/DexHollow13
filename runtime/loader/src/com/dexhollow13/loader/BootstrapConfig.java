package com.dexhollow13.loader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 解析 assets/.d13/0.dat 解密后的内层启动格式。
 *
 * 这个类必须位于 Loader DEX，因为 Framework 创建目标 ClassLoader 以前，原 APK 的类还不可见。
 * Java 与 Host C++ 使用相同的显式小端格式，避免 Java DataInputStream 默认大端造成歧义。
 */
final class BootstrapConfig {
    private static final byte[] MAGIC = new byte[] {'D', 'H', '1', '3', 'B', 'O', 'O', 'T'};
    private static final int VERSION = 1;
    private static final int HEADER_SIZE = 48;
    private static final int DEX_RECORD_HEADER_SIZE = 64;
    // 这是 APK 中唯一固定的壳资源名。DEX/Payload 使用每次打包随机的
    // .dat 名称，只有解密这份索引后才能知道它们各自的路径。
    private static final String BOOTSTRAP_ENTRY = "assets/.d13/0.dat";

    static final class DexRecord {
        final int ordinal;
        final int protectedMethodCount;
        final String hollowDexAsset;
        final String payloadAsset;
        final byte[] originalSignature;
        final byte[] hollowSignature;

        DexRecord(int ordinal, int protectedMethodCount, String hollowDexAsset, String payloadAsset,
            byte[] originalSignature, byte[] hollowSignature) {
            this.ordinal = ordinal;
            this.protectedMethodCount = protectedMethodCount;
            this.hollowDexAsset = hollowDexAsset;
            this.payloadAsset = payloadAsset;
            this.originalSignature = originalSignature;
            this.hollowSignature = hollowSignature;
        }
    }

    final String packageName;
    final String originalApplication;
    final String originalAppComponentFactory;
    final List<DexRecord> dexFiles;

    private BootstrapConfig(String packageName, String originalApplication,
        String originalAppComponentFactory, List<DexRecord> dexFiles) {
        this.packageName = packageName;
        this.originalApplication = originalApplication;
        this.originalAppComponentFactory = originalAppComponentFactory;
        this.dexFiles = Collections.unmodifiableList(dexFiles);
    }

    static BootstrapConfig readFromApk(String apkPath) {
        try (ZipFile apk = new ZipFile(apkPath)) {
            ZipEntry entry = apk.getEntry(BOOTSTRAP_ENTRY);
            if (entry == null) {
                throw new IllegalStateException("APK 缺少 " + BOOTSTRAP_ENTRY);
            }
            try (InputStream input = apk.getInputStream(entry)) {
                byte[] sealed = readAll(input, entry.getSize());
                byte[] plaintext = null;
                try {
                    plaintext =
                        NativeBridge.decryptResource(sealed, NativeBridge.RESOURCE_BOOTSTRAP, 0);
                    return parse(plaintext);
                } finally {
                    Arrays.fill(sealed, (byte) 0);
                    if (plaintext != null) {
                        Arrays.fill(plaintext, (byte) 0);
                    }
                }
            }
        } catch (IOException error) {
            throw new IllegalStateException("读取加密启动索引失败", error);
        }
    }

    private static byte[] readAll(InputStream input, long declaredSize) throws IOException {
        if (declaredSize > Integer.MAX_VALUE) {
            throw new IllegalStateException("加密启动索引过大");
        }
        int initialSize = declaredSize > 0 ? (int) declaredSize : 1024;
        ByteArrayOutputStream output = new ByteArrayOutputStream(initialSize);
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static BootstrapConfig parse(byte[] bytes) {
        if (bytes.length < HEADER_SIZE) {
            throw new IllegalStateException("启动索引明文小于固定 Header");
        }
        ByteBuffer input = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        for (byte expected : MAGIC) {
            if (input.get() != expected) {
                throw new IllegalStateException("bootstrap magic 不正确");
            }
        }

        int version = input.getInt();
        int headerSize = input.getInt();
        int flags = input.getInt();
        int dexCount = input.getInt();
        int packageLength = input.getInt();
        int applicationLength = input.getInt();
        int factoryLength = input.getInt();
        int fileSize = input.getInt();
        int bodyCrc = input.getInt();
        int reserved = input.getInt();

        if (version != VERSION || headerSize != HEADER_SIZE || flags != 0 || reserved != 0
            || dexCount <= 0 || fileSize != bytes.length) {
            throw new IllegalStateException("bootstrap Header 字段不受支持");
        }
        requireNonNegative(packageLength, "packageLength");
        requireNonNegative(applicationLength, "applicationLength");
        requireNonNegative(factoryLength, "factoryLength");

        CRC32 crc32 = new CRC32();
        crc32.update(bytes, HEADER_SIZE, bytes.length - HEADER_SIZE);
        if ((int) crc32.getValue() != bodyCrc) {
            throw new IllegalStateException("bootstrap body CRC32 不正确");
        }

        String packageName = readString(input, packageLength, "packageName");
        String applicationName = readString(input, applicationLength, "originalApplication");
        String factoryName = readString(input, factoryLength, "originalAppComponentFactory");
        skipFourBytePadding(input, "bootstrap strings");
        if (packageName.isEmpty() || applicationName.isEmpty()) {
            throw new IllegalStateException("bootstrap 的 package/Application 不能为空");
        }

        ArrayList<DexRecord> records = new ArrayList<>(dexCount);
        for (int index = 0; index < dexCount; ++index) {
            requireRemaining(input, DEX_RECORD_HEADER_SIZE, "DEX record header");
            int ordinal = input.getInt();
            int protectedCount = input.getInt();
            int dexNameLength = input.getInt();
            int payloadNameLength = input.getInt();
            int recordFlags = input.getInt();
            int recordReserved = input.getInt();
            requireNonNegative(ordinal, "DEX ordinal");
            requireNonNegative(protectedCount, "protected method count");
            requireNonNegative(dexNameLength, "DEX asset name length");
            requireNonNegative(payloadNameLength, "Payload asset name length");
            if (recordFlags != 0 || recordReserved != 0) {
                throw new IllegalStateException("DEX record flags/reserved 非 0");
            }

            byte[] originalSignature = new byte[20];
            byte[] hollowSignature = new byte[20];
            input.get(originalSignature);
            input.get(hollowSignature);
            String dexAsset = readString(input, dexNameLength, "Hollow DEX asset name");
            String payloadAsset = readString(input, payloadNameLength, "Payload asset name");
            skipFourBytePadding(input, "DEX record");
            if (dexAsset.isEmpty() || payloadAsset.isEmpty()) {
                throw new IllegalStateException("DEX/Payload asset name 不能为空");
            }
            records.add(new DexRecord(ordinal, protectedCount, dexAsset, payloadAsset,
                originalSignature, hollowSignature));
        }
        if (input.hasRemaining()) {
            throw new IllegalStateException("bootstrap 尾部存在未定义数据");
        }

        // Host 写入时已经按 classes.dex、classes2.dex... 排序；这里再次要求 ordinal 连续，
        // 既能发现损坏，也避免在最早启动阶段生成 lambda/匿名 Comparator 辅助类。
        for (int index = 0; index < records.size(); ++index) {
            if (records.get(index).ordinal != index) {
                throw new IllegalStateException("DEX ordinal 必须从 0 连续排列");
            }
        }
        return new BootstrapConfig(packageName, applicationName, factoryName, records);
    }

    private static String readString(ByteBuffer input, int length, String field) {
        requireRemaining(input, length, field);
        byte[] bytes = new byte[length];
        input.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static void skipFourBytePadding(ByteBuffer input, String field) {
        while ((input.position() & 3) != 0) {
            requireRemaining(input, 1, field + " padding");
            if (input.get() != 0) {
                throw new IllegalStateException(field + " padding 必须为 0");
            }
        }
    }

    private static void requireRemaining(ByteBuffer input, int count, String field) {
        if (count < 0 || input.remaining() < count) {
            throw new IllegalStateException(field + " 越界");
        }
    }

    private static void requireNonNegative(int value, String field) {
        if (value < 0) {
            throw new IllegalStateException(field + " 超过 Java int 范围");
        }
    }
}
