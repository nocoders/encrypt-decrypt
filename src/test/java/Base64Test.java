import com.crop.Base64Util;
import org.junit.jupiter.api.Test;

/**
 * @author linmeng
 * @date 2022/5/8 22:06
 */
public class Base64Test {
    @Test
    public void base64Test(){
        String s = "Java加密和解密的艺术";
        String bouncyCastleEncode = Base64Util.bouncyCastleEncode(s);
        String bouncyCastleDecode = Base64Util.bouncyCastleDecode(bouncyCastleEncode);
        System.out.println("bouncyCastleEncode:"+bouncyCastleEncode);
        System.out.println("bouncyCastleDecode:"+bouncyCastleDecode);
        String codecEncode = Base64Util.codecEncode(s);
        String codecDecode = Base64Util.codecDecode(codecEncode);
        System.out.println("codecEncode:"+codecEncode);
        System.out.println("codecDecode:"+codecDecode);
    }
    @Test
    public void UrlBase64Test(){
        String s = "Java加密和解密的艺术";
        String bouncyCastleEncode = Base64Util.bouncyCastleUrlEncode(s);
        String bouncyCastleDecode = Base64Util.bouncyCastleUrlDecode(bouncyCastleEncode);
        System.out.println("bouncyCastleEncode:"+bouncyCastleEncode);
        System.out.println("bouncyCastleDecode:"+bouncyCastleDecode);
        String codecEncode = Base64Util.codecUrlEncode(s);
        String codecDecode = Base64Util.codecUrlDecode(codecEncode);
        System.out.println("codecEncode:"+codecEncode);
        System.out.println("codecDecode:"+codecDecode);
    }
}
