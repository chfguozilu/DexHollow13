package com.dexhollow13.loader;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.util.Log;
import dalvik.system.InMemoryDexClassLoader;
import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Android 13 的公开启动扩展点，也是 DexHollow13 最早执行的 Loader 类。
 *
 * LoadedApk 先用根 classes.dex 所在 PathClassLoader 创建本 Factory，然后调用
 * instantiateClassLoader()。因此这里可以在 Application、Provider、Activity 之前读取 assets
 * 中的全部 Hollow DEX，返回一个统一的 InMemoryDexClassLoader，并安装进程内 ART hook。
 */
public final class ShellComponentFactory extends AppComponentFactory {
    private static final String LOG_TAG = "DexHollow13";
    private static final String SHELL_APPLICATION = "com.dexhollow13.loader.ShellApplication";

    // 静态强引用保证 DirectByteBuffer、目标 ClassLoader 和原 Factory 在进程整个生命周期有效。
    private static volatile BootstrapConfig config;
    private static volatile ApkBuffers buffers;
    private static volatile ClassLoader targetClassLoader;
    private static volatile AppComponentFactory originalFactory;

    @Override
    public ClassLoader instantiateClassLoader(
        ClassLoader defaultClassLoader, ApplicationInfo applicationInfo) {
        synchronized (ShellComponentFactory.class) {
            if (targetClassLoader != null) {
                return targetClassLoader;
            }

            BootstrapConfig loadedConfig = BootstrapConfig.readFromApk(applicationInfo.sourceDir);
            ApkBuffers loadedBuffers = ApkBuffers.read(
                applicationInfo.sourceDir, applicationInfo.dataDir, loadedConfig.dexFiles);

            // InMemoryDexClassLoader(ByteBuffer[]) 一次承载全部 classes*.dex，并保持原顺序。
            //
            // 这里必须使用带 librarySearchPath 的三参数构造函数。ClassLoader 的 parent 只参与
            // Java 类的双亲委派；System.loadLibrary() 会根据“发起调用的类所属 ClassLoader”调用
            // findLibrary()，不会自动把父 PathClassLoader 的 nativeLibraryDirectories 复制给子
            // Loader。若使用两参数构造函数，业务类虽然能运行，却只能搜索系统 SO，APK 自带的
            // lib/<abi>/*.so 会报 UnsatisfiedLinkError。
            // 必须在构造 InMemoryDexClassLoader 之前安装 Hook。大型应用的真实启动验证表明，
            // ART 在打开一组 InMemory DEX 的过程中可能已经定义启动相关类；如果等构造函数
            // 返回后再 Hook，这些类的 ArtMethod 已经越过唯一一次 LoadMethod 初始化机会。
            // Native 初始化只解析 mmap 中的 DEX identity 与 Payload，不依赖 ART DexFile 已存在。
            NativeBridge.initialize(loadedBuffers.hollowDexBuffers, loadedBuffers.payloadBuffers);

            ByteBuffer[] dexInputs = duplicateBuffers(loadedBuffers.hollowDexBuffers);
            String nativeLibrarySearchPath = buildNativeLibrarySearchPath(applicationInfo);
            ClassLoader hollowLoader =
                new InMemoryDexClassLoader(dexInputs, nativeLibrarySearchPath, defaultClassLoader);

            long boundBeforeFactory = NativeBridge.boundMethodCount();
            AppComponentFactory delegate =
                createOriginalFactory(loadedConfig.originalAppComponentFactory, hollowLoader);
            Log.i(LOG_TAG,
                "Original AppComponentFactory created: "
                    + (delegate == null ? "<none>" : delegate.getClass().getName())
                    + ", usesHollowLoader="
                    + (delegate != null && delegate.getClass().getClassLoader() == hollowLoader)
                    + ", newly-bound methods="
                    + (NativeBridge.boundMethodCount() - boundBeforeFactory));
            ClassLoader finalLoader = hollowLoader;
            if (delegate != null) {
                finalLoader = delegate.instantiateClassLoader(hollowLoader, applicationInfo);
                if (finalLoader == null) {
                    throw new IllegalStateException(
                        "原 AppComponentFactory 返回了 null ClassLoader");
                }
            }

            config = loadedConfig;
            buffers = loadedBuffers;
            originalFactory = delegate;
            targetClassLoader = finalLoader;
            return finalLoader;
        }
    }

    @Override
    public Application instantiateApplication(ClassLoader classLoader, String className)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        BootstrapConfig current = requireConfig();
        String requestedClass =
            SHELL_APPLICATION.equals(className) ? current.originalApplication : className;
        AppComponentFactory delegate = originalFactory;
        if (delegate != null) {
            long boundBeforeApplication = NativeBridge.boundMethodCount();
            Application application = delegate.instantiateApplication(classLoader, requestedClass);
            Log.i(LOG_TAG,
                "Original instantiateApplication returned "
                    + (application == null ? "null" : application.getClass().getName())
                    + ", newly-bound methods="
                    + (NativeBridge.boundMethodCount() - boundBeforeApplication));
            return application;
        }
        return super.instantiateApplication(classLoader, requestedClass);
    }

    @Override
    public Activity instantiateActivity(ClassLoader classLoader, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = originalFactory;
        return delegate != null ? delegate.instantiateActivity(classLoader, className, intent)
                                : super.instantiateActivity(classLoader, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader classLoader, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = originalFactory;
        return delegate != null ? delegate.instantiateService(classLoader, className, intent)
                                : super.instantiateService(classLoader, className, intent);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(
        ClassLoader classLoader, String className, Intent intent)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = originalFactory;
        return delegate != null ? delegate.instantiateReceiver(classLoader, className, intent)
                                : super.instantiateReceiver(classLoader, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader classLoader, String className)
        throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = originalFactory;
        return delegate != null ? delegate.instantiateProvider(classLoader, className)
                                : super.instantiateProvider(classLoader, className);
    }

    private static BootstrapConfig requireConfig() {
        BootstrapConfig current = config;
        if (current == null) {
            throw new IllegalStateException("instantiateClassLoader 尚未完成");
        }
        return current;
    }

    private static ByteBuffer[] duplicateBuffers(ByteBuffer[] source) {
        ByteBuffer[] result = new ByteBuffer[source.length];
        for (int index = 0; index < source.length; ++index) {
            // duplicate() 共享同一块 DirectBuffer 内存，但拥有独立 position/limit，防止
            // InMemoryDexClassLoader 改变 position 后影响 JNI 对原 Buffer 的读取。
            result[index] = source[index].duplicate();
        }
        return result;
    }

    /**
     * 为业务 InMemoryDexClassLoader 重建 Android 13 LoadedApk 使用的核心 Native 搜索路径。
     *
     * 第一项 applicationInfo.nativeLibraryDir 覆盖 extractNativeLibs=true：PackageManager 会把
     * SO 解压到安装目录。第二类 "base.apk!/lib/<abi>" 路径覆盖 extractNativeLibs=false：
     * linker 直接 mmap APK 中保持 Stored 且已对齐的 SO。本项目只支持 arm64-v8a 与
     * armeabi-v7a，因此可以由当前进程位数唯一确定 PackageManager 选择的 ABI。
     */
    private static String buildNativeLibrarySearchPath(ApplicationInfo applicationInfo) {
        Set<String> paths = new LinkedHashSet<>();
        addNonEmptyPath(paths, applicationInfo.nativeLibraryDir);

        String processAbi = Process.is64Bit() ? "arm64-v8a" : "armeabi-v7a";
        addApkNativeLibraryPath(paths, applicationInfo.sourceDir, processAbi);

        // DexHollow13 当前只接受单个 base APK，但把已安装 split 的路径也纳入搜索没有副作用，
        // 并且与 Android 13 LoadedApk.makePaths() 对 native 路径的处理保持一致。
        if (applicationInfo.splitSourceDirs != null) {
            for (String splitSourceDir : applicationInfo.splitSourceDirs) {
                addApkNativeLibraryPath(paths, splitSourceDir, processAbi);
            }
        }

        StringBuilder joined = new StringBuilder();
        for (String path : paths) {
            if (joined.length() != 0) {
                joined.append(File.pathSeparatorChar);
            }
            joined.append(path);
        }
        return joined.toString();
    }

    private static void addApkNativeLibraryPath(Set<String> paths, String apkPath, String abi) {
        if (apkPath != null && !apkPath.isEmpty()) {
            paths.add(apkPath + "!/lib/" + abi);
        }
    }

    private static void addNonEmptyPath(Set<String> paths, String path) {
        if (path != null && !path.isEmpty()) {
            paths.add(path);
        }
    }

    private static AppComponentFactory createOriginalFactory(
        String className, ClassLoader classLoader) {
        if (className == null || className.isEmpty()) {
            return null;
        }
        if (ShellComponentFactory.class.getName().equals(className)) {
            throw new IllegalStateException("输入 APK 已经使用 DexHollow13 ShellComponentFactory");
        }
        try {
            Class<?> factoryClass = Class.forName(className, true, classLoader);
            if (!AppComponentFactory.class.isAssignableFrom(factoryClass)) {
                throw new IllegalStateException(className + " 不是 AppComponentFactory");
            }
            Constructor<?> constructor = factoryClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (AppComponentFactory) constructor.newInstance();
        } catch (ReflectiveOperationException error) {
            throw new IllegalStateException("创建原 AppComponentFactory 失败：" + className, error);
        }
    }
}
