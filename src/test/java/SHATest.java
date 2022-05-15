import com.crop.sha.SHAUtil;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

/**
 * @author linmeng
 * @date 2022/5/15 15:16
 */

public class SHATest {
    @Test
    public void jdkTest() throws NoSuchAlgorithmException {
        System.out.println("jdk");
        System.out.println(SHAUtil.jdkSHA1("java加密与解密"));
        System.out.println(SHAUtil.jdkSHA224("java加密与解密"));
        System.out.println(SHAUtil.jdkSHA256("java加密与解密"));
        System.out.println(SHAUtil.jdkSHA384("java加密与解密"));
        System.out.println(SHAUtil.jdkSHA512("java加密与解密"));
        System.out.println("bouncy castle");
        System.out.println(SHAUtil.bouncyCastleSha224("java加密与解密"));
        System.out.println("codec");
        System.out.println(SHAUtil.codecSHA1("java加密与解密"));
        System.out.println(SHAUtil.codecSHA256("java加密与解密"));
        System.out.println(SHAUtil.codecSHA384("java加密与解密"));
        System.out.println(SHAUtil.codecSHA512("java加密与解密"));
        System.out.println(SHAUtil.codecSHA3224("java加密与解密"));
        System.out.println(SHAUtil.codecSHA3256("java加密与解密"));
        System.out.println(SHAUtil.codecSHA3384("java加密与解密"));
        System.out.println(SHAUtil.codecSHA3512("java加密与解密"));
    }
}
