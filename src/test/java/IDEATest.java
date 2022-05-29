import org.junit.jupiter.api.Test;

import static com.crop.IDEAUtil.*;

/**
 * IDEA 测试类
 * @author linmeng
 * @date 2022/5/22 23:07
 */
public class IDEATest {
    @Test
    public void jdkTest() throws Exception{
        String keyStr = initKey();
        String str = "Java 加密解密";
        String message = encrypt(str, keyStr);
        System.out.println("加密数据："+message);
        String decryptStr = decrypt(message, keyStr);
        System.out.println("解密数据："+decryptStr);

    }

}
