#pragma once

#include <stdexcept>
#include <string>

namespace dexhollow13 {

// Error 表示 DexHollow13 能够识别并向用户解释的失败。
//
// 这里暂时沿用异常而不是引入复杂的 Result<T> 模板，原因是 Host 工具的调用链较深，
// 每一层都手工转发错误会掩盖真正的 DEX offset。main() 会在最外层捕获这个异常，
// 打印一条干净的错误信息并返回非零退出码。
class Error final : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

}  // namespace dexhollow13
