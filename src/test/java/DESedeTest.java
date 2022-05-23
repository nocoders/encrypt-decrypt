import org.junit.jupiter.api.Test;

import static com.crop.DESedeUtil.*;

/**
 * DES 测试类
 * @author linmeng
 * @date 2022/5/22 23:07
 */
public class DESedeTest {
    @Test
    public void jdkTest() throws Exception{
        decryptAndEncrypt(false);
        decryptAndEncrypt(true);

    }

    private void decryptAndEncrypt(boolean isBouncyCastle) throws Exception {
        String keyStr = initKey(isBouncyCastle);
        System.out.println("密钥："+keyStr);
        String str = "Java 加密解密";
        String message = encrypt(str, keyStr);
        System.out.println("加密数据："+message);
        String decryptStr = decrypt(message, keyStr);
        System.out.println("解密数据："+decryptStr);
    }
}
