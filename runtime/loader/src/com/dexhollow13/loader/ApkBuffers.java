package com.dexhollow13.loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** 从 APK 的加密 assets 构建 InMemoryDexClassLoader 与 Native Runtime 使用的文件映射。 */
final class ApkBuffers {
    private static final int COPY_BUFFER_SIZE = 64 * 1024;

    final ByteBuffer[] hollowDexBuffers;
    final ByteBuffer[] payloadBuffers;

    private ApkBuffers(ByteBuffer[] hollowDexBuffers, ByteBuffer[] payloadBuffers) {
        this.hollowDexBuffers = hollowDexBuffers;
        this.payloadBuffers = payloadBuffers;
    }

    static ApkBuffers read(
        String apkPath, String appDataDir, List<BootstrapConfig.DexRecord> records) {
        if (appDataDir == null || appDataDir.isEmpty()) {
            throw new IllegalStateException("ApplicationInfo.dataDir 为空");
        }

        // code_cache 属于应用私有目录，系统可以在存储紧张时清理；文件消失后下次启动会从
        // APK 重新生成。这里不使用 filesDir，是为了明确这些文件只是可再生运行时缓存。
        File cacheDir = new File(new File(appDataDir, "code_cache"), "dexhollow13");
        ensureDirectory(cacheDir);

        ByteBuffer[] dexBuffers = new ByteBuffer[records.size()];
        ByteBuffer[] payloadBuffers = new ByteBuffer[records.size()];
        Set<String> expectedFiles = new HashSet<>();
        byte[] copyBuffer = new byte[COPY_BUFFER_SIZE];

        // 同一个 APK 的多个进程可能同时进入 instantiateClassLoader。文件锁把提取、原子改名
        // 和旧缓存清理串行化，避免一个进程 mmap 到另一个进程尚未写完的文件。
        File lockPath = new File(cacheDir, ".lock");
        try (RandomAccessFile lockFile = new RandomAccessFile(lockPath, "rw");
            FileChannel lockChannel = lockFile.getChannel(); FileLock ignored = lockChannel.lock();
            ZipFile apk = new ZipFile(apkPath)) {
            for (int index = 0; index < records.size(); ++index) {
                BootstrapConfig.DexRecord record = records.get(index);
                String dexEntryName = toZipAssetName(record.hollowDexAsset);
                String payloadEntryName = toZipAssetName(record.payloadAsset);
                ZipEntry dexEntry = requireEntry(apk, dexEntryName);
                ZipEntry payloadEntry = requireEntry(apk, payloadEntryName);
                String dexCacheName = buildDexCacheName(record, dexEntry);
                String payloadCacheName = buildPayloadCacheName(record, payloadEntry);
                expectedFiles.add(dexCacheName);
                expectedFiles.add(payloadCacheName);

                File encryptedDexCache = new File(cacheDir, dexCacheName);
                extractEncryptedAsset(apk, dexEntry, dexEntryName, encryptedDexCache, copyBuffer);
                dexBuffers[index] = decryptDexAndMap(encryptedDexCache, cacheDir, record.ordinal);

                File encryptedPayloadCache = new File(cacheDir, payloadCacheName);
                extractEncryptedAsset(
                    apk, payloadEntry, payloadEntryName, encryptedPayloadCache, copyBuffer);
                // Payload record table 和 code_item 都保持密文映射。Native 初始化只认证并
                // 建立索引；具体方法被 ART LoadMethod 加载时才解密那一个 code_item。
                payloadBuffers[index] = mapReadOnly(encryptedPayloadCache, payloadEntryName);
            }
            removeStaleCacheFiles(cacheDir, expectedFiles);
        } catch (IOException error) {
            throw new IllegalStateException("映射 Hollow DEX/Payload assets 失败", error);
        }
        return new ApkBuffers(dexBuffers, payloadBuffers);
    }

    private static void ensureDirectory(File directory) {
        if ((!directory.isDirectory() && !directory.mkdirs()) || !directory.isDirectory()) {
            throw new IllegalStateException("无法创建 DexHollow13 缓存目录：" + directory);
        }
    }

    private static String toZipAssetName(String assetName) {
        if (assetName.startsWith("/") || assetName.contains("..")) {
            throw new IllegalStateException("bootstrap 包含非法 asset 路径：" + assetName);
        }
        return "assets/" + assetName;
    }

    private static ZipEntry requireEntry(ZipFile apk, String entryName) {
        ZipEntry entry = apk.getEntry(entryName);
        if (entry == null) {
            throw new IllegalStateException("APK 缺少 " + entryName);
        }
        if (entry.getSize() <= 0 || entry.getSize() > Integer.MAX_VALUE || entry.getCrc() < 0) {
            throw new IllegalStateException("APK entry 大小/CRC 非法：" + entryName);
        }
        return entry;
    }

    private static String entryIdentity(ZipEntry entry) {
        // 加密使用随机 nonce，同一 Hollow signature 再次打包也会得到不同 ciphertext。
        // 把 ZIP CRC 与长度放进缓存名，APK 更新后不会错误复用上一包的密文。
        return Long.toHexString(entry.getCrc()) + "-" + Long.toHexString(entry.getSize());
    }

    private static String buildDexCacheName(BootstrapConfig.DexRecord record, ZipEntry entry) {
        // Hollow signature 会在每次变换后改变，因此 APK 更新后自然使用不同文件名，不会把
        // 上一版本的 DEX 缓存误交给 ART。
        return "dex-" + record.ordinal + "-" + toHex(record.hollowSignature) + "-"
            + entryIdentity(entry) + ".enc";
    }

    private static String buildPayloadCacheName(BootstrapConfig.DexRecord record, ZipEntry entry) {
        // Payload 同时绑定原始和 Hollow DEX signature。两者都进入文件名，使缓存身份与
        // Native 层执行的 identity 校验一致。
        return "payload-" + record.ordinal + "-" + toHex(record.originalSignature) + "-"
            + toHex(record.hollowSignature) + "-" + entryIdentity(entry) + ".enc";
    }

    private static String toHex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] output = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; ++index) {
            int value = bytes[index] & 0xff;
            output[index * 2] = digits[value >>> 4];
            output[index * 2 + 1] = digits[value & 0x0f];
        }
        return new String(output);
    }

    private static void extractEncryptedAsset(ZipFile apk, ZipEntry entry, String entryName,
        File cacheFile, byte[] copyBuffer) throws IOException {
        long declaredSize = entry.getSize();
        if (!cacheFile.isFile() || cacheFile.length() != declaredSize) {
            writeCacheAtomically(apk, entry, entryName, cacheFile, declaredSize, copyBuffer);
        }
    }

    private static ByteBuffer mapReadOnly(File file, String purpose) throws IOException {
        long size = file.length();
        if (size <= 0 || size > Integer.MAX_VALUE) {
            throw new IllegalStateException("映射文件大小非法：" + purpose + "，size=" + size);
        }
        // FileChannel.map 创建的是文件支持的 MappedByteBuffer，不会像 allocateDirect() 那样
        // 调用 VMRuntime.newNonMovableArray 并消耗 Android 的 Java heap growth limit。
        try (FileInputStream input = new FileInputStream(file)) {
            ByteBuffer mapped = input.getChannel().map(FileChannel.MapMode.READ_ONLY, 0L, size);
            if (!mapped.isDirect() || mapped.capacity() != (int) size) {
                throw new IllegalStateException("mmap 未返回预期 DirectByteBuffer：" + purpose);
            }
            return mapped;
        }
    }

    private static ByteBuffer decryptDexAndMap(File encryptedCache, File cacheDir, int ordinal)
        throws IOException {
        File plaintext = File.createTempFile("dex-" + ordinal + "-", ".plain", cacheDir);
        try {
            NativeBridge.decryptResourceFile(encryptedCache.getAbsolutePath(),
                plaintext.getAbsolutePath(), NativeBridge.RESOURCE_HOLLOW_DEX, ordinal);
            ByteBuffer mapped = mapReadOnly(plaintext, "Hollow DEX #" + ordinal);
            // Linux/Android 允许 unlink 已 mmap 的文件。映射和 ART 后续复制仍然有效，但
            // code_cache 目录不会留下可被离线直接读取的 Hollow DEX 明文。
            if (!plaintext.delete()) {
                throw new IllegalStateException("无法删除 Hollow DEX 明文临时文件：" + plaintext);
            }
            return mapped;
        } finally {
            if (plaintext.exists() && !plaintext.delete()) {
                plaintext.deleteOnExit();
            }
        }
    }

    private static void writeCacheAtomically(ZipFile apk, ZipEntry entry, String entryName,
        File cacheFile, long declaredSize, byte[] copyBuffer) throws IOException {
        File temporary = File.createTempFile("extract-", ".tmp", cacheFile.getParentFile());
        boolean committed = false;
        try {
            long total = 0L;
            try (InputStream input = apk.getInputStream(entry);
                FileOutputStream output = new FileOutputStream(temporary)) {
                int count;
                while ((count = input.read(copyBuffer)) != -1) {
                    if (total + count > declaredSize) {
                        throw new IllegalStateException(
                            "APK entry 解压大小超过 central directory：" + entryName);
                    }
                    output.write(copyBuffer, 0, count);
                    total += count;
                }
                output.flush();
                output.getFD().sync();
            }
            if (total != declaredSize) {
                throw new IllegalStateException("APK entry 实际大小与声明不一致：" + entryName);
            }

            if (cacheFile.exists() && !cacheFile.delete()) {
                throw new IllegalStateException("无法替换旧缓存文件：" + cacheFile);
            }
            if (!temporary.renameTo(cacheFile)) {
                throw new IllegalStateException("无法提交缓存文件：" + cacheFile);
            }
            committed = true;
        } finally {
            if (!committed && temporary.exists() && !temporary.delete()) {
                temporary.deleteOnExit();
            }
        }
    }

    private static void removeStaleCacheFiles(File cacheDir, Set<String> expectedFiles) {
        File[] files = cacheDir.listFiles();
        if (files == null) {
            throw new IllegalStateException("无法枚举 DexHollow13 缓存目录：" + cacheDir);
        }
        for (File file : files) {
            String name = file.getName();
            if (file.isFile() && !".lock".equals(name) && !expectedFiles.contains(name)
                && !file.delete()) {
                throw new IllegalStateException("无法删除过期 DexHollow13 缓存：" + file);
            }
        }
    }
}
