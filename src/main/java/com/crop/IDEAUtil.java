package com.crop;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * IDEA 算法实现
 * @author linmeng
 * @date 2022/5/29 20:03
 */

public class IDEAUtil {
    /* 密钥算法*/
    private static final String KEY_ALGORITHM = "IDEA";
    /*加密解密算法/工作方式/填充模式*/
    // JDK 支持PKCS5Padding填充模式
    private static final String CIPHER_ALGORITHM = "IDEA/ECB/ISO10126Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 根据算法生成密钥
     *
     * @return
     */
    public static String initKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        return Hex.encodeHexString(secretKey.getEncoded());
    }

    /**
     * 根据16进制生成的密钥字符串和算法还原密钥
     *
     * @param keyStr
     * @return
     */
    public static SecretKey restoreKey(String keyStr) throws Exception {
        byte[] bytesKey = Hex.decodeHex(keyStr);

        return new SecretKeySpec(bytesKey,KEY_ALGORITHM);
    }

    /**
     * 生成Base加密字符串
     *
     * @param str
     * @param keyStr
     * @return
     */
    public static String encrypt(String str, String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return Base64.encodeBase64String(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 对加密数据进行解密
     *
     * @param message 已加密数据
     * @param keyStr  密钥字符串
     * @return 解密数据
     */
    public static String decrypt(String message, String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return new String(cipher.doFinal(Base64.decodeBase64(message)));
    }
}
