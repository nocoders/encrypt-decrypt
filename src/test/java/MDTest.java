import com.crop.MDUtil;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

/**
 * @author linmeng
 * @date 2022/5/11 23:17
 */

public class MDTest {

    @Test
    public void jdkMd5Test() throws NoSuchAlgorithmException {
        String str = "Java 加密解密的艺术";
        System.out.println( MDUtil.jdkMd5(str));
        System.out.println(MDUtil.bouncyCastleMd5(str));
        System.out.println(MDUtil.codecMd5(str));
    }
}
