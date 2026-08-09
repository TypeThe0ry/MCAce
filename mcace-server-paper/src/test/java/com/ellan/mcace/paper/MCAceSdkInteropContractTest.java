package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.sdk.MCAceInterop;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

final class MCAceSdkInteropContractTest {
    @Test
    void pluginExposesJdkOnlyVersionOneInteropMethod() throws Exception {
        var method = MCAcePaperPlugin.class.getMethod(MCAceInterop.PROVIDER_METHOD_V1);
        assertEquals(Function.class, method.getReturnType());
        assertEquals(0, method.getParameterCount());
    }
}
