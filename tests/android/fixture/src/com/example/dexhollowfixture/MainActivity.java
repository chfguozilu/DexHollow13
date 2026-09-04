package com.example.dexhollowfixture;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** 不依赖项目资源的真机入口，方便把失败范围收敛到 DEX/Runtime 而不是资源加载。 */
public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Secret secret = new Secret(true);
        int answer = secret.addTen(1);
        long wide = secret.wide(2L);
        int caught = Secret.withCatch("not-a-number");
        String secondary = SecondarySecret.token();
        boolean objectOk = secret.nullable(true) == secret;
        int controlFlow = secret.packedSwitch(2) + secret.sparseSwitch(100000);
        int array = secret.arrayPayload();
        int nativeResult = BusinessNative.plusSeven(42);

        // 超过常见 JIT 热点阈值。受保护方法带 kAccCompileDontBother，重复调用后仍应从
        // Shadow CodeItem 解释执行，结果也能发现 entrypoint 被错误替换的问题。
        int hot = 0;
        for (int index = 0; index < 20000; ++index) {
            hot = secret.synchronizedMethod(index);
        }

        TextView text = new TextView(this);
        text.setText("answer=" + answer + ", wide=" + wide + ", caught=" + caught
            + ", secondary=" + secondary + ", object=" + objectOk + ", control=" + controlFlow
            + ", array=" + array + ", native=" + nativeResult + ", hot=" + hot);
        setContentView(text);
    }
}
