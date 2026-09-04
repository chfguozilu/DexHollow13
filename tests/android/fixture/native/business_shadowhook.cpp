// 故意生成原始名称 libshadowhook.so，模拟业务 APK 已经集成自己的 ShadowHook。
// fixturebusiness 对这个符号存在真实 ELF 依赖，保证测试不只是检查 ZIP 文件名能否共存。
extern "C" int fixture_shadowhook_marker() { return 5; }
