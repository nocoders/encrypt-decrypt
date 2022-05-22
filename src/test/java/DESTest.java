import static com.crop.DESUtil.*;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * DES 测试类
 * @author linmeng
 * @date 2022/5/22 23:07
 */
public class DESTest {
    @Test
    public void jdkTest() throws Exception{
        decryptAndEncrypt(false);
        decryptAndEncrypt(true);

    }

    private void decryptAndEncrypt(boolean isBouncyCastle) throws Exception {
        String keyStr = initKey(isBouncyCastle);
        String str = "Java 加密解密";
        String message = encrypt(str, keyStr);
        System.out.println("加密数据："+message);
        String decryptStr = decrypt(message, keyStr);
        System.out.println("解密数据："+decryptStr);
    }
}
