// 真实 ShadowHook 还会携带 libshadowhook_nothing.so。这个最小导出只用于让测试 APK 同时
// 占用该文件名，验证加壳器不会覆盖或拒绝业务自己的辅助库。
extern "C" int fixture_shadowhook_nothing_marker() { return 1; }
