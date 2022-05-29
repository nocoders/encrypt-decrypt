import static com.crop.RSAUtil.*;

import javafx.util.Pair;
import org.junit.jupiter.api.Test;

/**
 * DES 测试类
 * @author linmeng
 * @date 2022/5/22 23:07
 */
public class RSATest {
    @Test
    public void jdkTest() throws Exception{
        Pair<String, String> keyPair = initKey();
        String privateKeyStr = keyPair.getKey();
        String publicKeyStr = keyPair.getValue();
        System.out.println("公钥："+ publicKeyStr);
        System.out.println("私钥："+ privateKeyStr);
        String str = "Java 加密和解密";
        String privateEncrypt = privateEncrypt(str,privateKeyStr);
        System.out.println("私钥加密："+ privateEncrypt);
        System.out.println("公要解密：" + publicDecrypt(privateEncrypt, publicKeyStr));
        String publicEncrypt = publicEncrypt(str,publicKeyStr);
        System.out.println("公钥加密："+ publicEncrypt);
        System.out.println("私钥解密：" + privateDecrypt(publicEncrypt, privateKeyStr));

    }
}
