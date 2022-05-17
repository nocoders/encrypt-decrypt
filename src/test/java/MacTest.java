import static com.crop.MacUtil.*;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author linmeng
 * @date 2022/5/17 21:43
 */

public class MacTest {
    public static String hmacMD2Algorithm = "HmacMD2";
    public static String hmacMD4Algorithm = "HmacMD4";
    public static String hmacMD5Algorithm = "HmacMD5";
    public static String hmacSHA1Algorithm = "HmacSHA1";
    public static String hmacSHA224Algorithm = "HmacSHA224";
    public static String hmacSHA256Algorithm = "HmacSHA256";
    public static String hmacSHA384Algorithm = "HmacSHA384";
    public static String hmacSHA512Algorithm = "HmacSHA512";
    @Test
    public void macTest() throws NoSuchAlgorithmException, DecoderException, InvalidKeyException {
        String message = "Java 加密和解密的艺术";
        String hmacMD2KeyStr = initKey(hmacMD2Algorithm);
        String hmacMd2DigestStr = encodeHex(message, hmacMD2KeyStr, hmacMD2Algorithm);
        System.out.printf("hmacMD2,密钥：%s,摘要：%s",hmacMD2KeyStr,hmacMd2DigestStr);
        System.out.println();
        String hmacMD4KeyStr = initKey(hmacMD4Algorithm);
        String hmacMd4DigestStr = encodeHex(message, hmacMD4KeyStr, hmacMD4Algorithm);
        System.out.printf("hmacMD4,密钥：%s,摘要：%s",hmacMD4KeyStr,hmacMd4DigestStr);
        System.out.println();
        String hmacMD5KeyStr = initKey(hmacMD5Algorithm);
        String hmacMd5DigestStr = encodeHex(message, hmacMD5KeyStr, hmacMD5Algorithm);
        System.out.printf("hmacMD5,密钥：%s,摘要：%s",hmacMD5KeyStr,hmacMd5DigestStr);
        System.out.println();
        String hmacSHA1KeyStr = initKey(hmacSHA1Algorithm);
        String hmacSHA1DigestStr = encodeHex(message, hmacSHA1KeyStr, hmacSHA1Algorithm);
        System.out.printf("hmacSHA1,密钥：%s,摘要：%s",hmacSHA1KeyStr,hmacSHA1DigestStr);
        System.out.println();
        String hmacSHA224KeyStr = initKey(hmacSHA224Algorithm);
        String hmacSHA224DigestStr = encodeHex(message, hmacSHA224KeyStr, hmacSHA224Algorithm);
        System.out.printf("hmacSHA224,密钥：%s,摘要：%s",hmacSHA224KeyStr,hmacSHA224DigestStr);
        System.out.println();
        String hmacSHA256KeyStr = initKey(hmacSHA256Algorithm);
        String hmacSHA256DigestStr = encodeHex(message, hmacSHA256KeyStr, hmacSHA256Algorithm);
        System.out.printf("hmacSHA256,密钥：%s,摘要：%s",hmacSHA256KeyStr,hmacSHA256DigestStr);
        System.out.println();
        String hmacSHA384KeyStr = initKey(hmacSHA384Algorithm);
        String hmacSHA384DigestStr = encodeHex(message, hmacSHA384KeyStr, hmacSHA384Algorithm);
        System.out.printf("hmacSHA384,密钥：%s,摘要：%s",hmacSHA384KeyStr,hmacSHA384DigestStr);
        System.out.println();
        String hmacSHA512KeyStr = initKey(hmacSHA512Algorithm);
        String hmacSHA512DigestStr = encodeHex(message, hmacSHA512KeyStr, hmacSHA512Algorithm);
        System.out.printf("hmacSHA512,密钥：%s,摘要：%s",hmacSHA512KeyStr,hmacSHA512DigestStr);
        System.out.println();
    }
}
