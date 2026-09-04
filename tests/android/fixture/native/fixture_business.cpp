#include <jni.h>

extern "C" int fixture_shadowhook_marker();

// 这是业务 APK 的 JNI 方法，不属于壳 Runtime。返回一个容易人工验证的值，既能证明
// System.loadLibrary() 找到了 APK 内的 libfixturebusiness.so，也能证明它通过 DT_NEEDED
// 加载并调用了业务自己的 libshadowhook.so，而不是 DexHollow13 内置的重命名版本。
extern "C" JNIEXPORT jint JNICALL Java_com_example_dexhollowfixture_BusinessNative_plusSeven(
    JNIEnv* /*environment*/, jclass /*type*/, jint value) {
    return value + fixture_shadowhook_marker() + 2;
}
