package com.example.dexhollowfixture;

/**
 * 六参数父构造器会迫使 D8 使用 invoke-direct/range，并通常先把 p0 搬到连续参数区。
 * 字段值又能证明 Runtime 最终执行的是父构造器的原始 Shadow CodeItem。
 */
class SecretBase {
    final int baseValue;

    SecretBase(int first, int second, int third, int fourth, int fifth, int sixth) {
        baseValue = first + second + third + fourth + fifth + sixth;
    }
}

/** 覆盖不同返回类型、异常表和静态/实例方法的最小业务类。 */
public final class Secret extends SecretBase {
    private final int constructorValue;

    public Secret(boolean chooseFirst) {
        // 三元表达式在 super() 前生成 if/goto；六个参数又会触发 /range 与 p0 move-object。
        super(chooseFirst ? 1 : 2, 3, 4, 5, 6, 7);

        // try/catch 位于 super() 之后，用于验证 Host 能保留初始化前缀、抽空构造器
        // 主体，并在 Runtime 通过 Shadow CodeItem 真正执行这里的字段赋值。
        int parsed;
        try {
            parsed = Integer.parseInt("5");
        } catch (NumberFormatException ignored) {
            parsed = 0;
        }
        constructorValue = parsed;
    }

    public int addTen(int value) {
        return value + 10 + constructorValue + baseValue;
    }

    public Object nullable(boolean returnValue) {
        return returnValue ? this : null;
    }

    public int packedSwitch(int value) {
        switch (value) {
            case 1:
                return 101;
            case 2:
                return 102;
            case 3:
                return 103;
            default:
                return -100;
        }
    }

    public int sparseSwitch(int value) {
        switch (value) {
            case -1000:
                return 7;
            case 100:
                return 8;
            case 100000:
                return 9;
            default:
                return -200;
        }
    }

    public int arrayPayload() {
        int[] values = {3, 5, 7, 11};
        return values[0] + values[3];
    }

    public synchronized int synchronizedMethod(int value) {
        return value * 2;
    }

    public long wide(long value) {
        return value + 0x123456789L;
    }

    public static int withCatch(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return -1;
        }
    }
}
