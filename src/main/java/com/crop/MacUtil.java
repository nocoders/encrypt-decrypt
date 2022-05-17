package com.crop;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Mac算法
 *
 * @author linmeng
 * @date 2022/5/15 21:57
 */

public class MacUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * 根据算法生成密钥
     *
     * @param algorithm
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String initKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        SecretKey secretKey = keyGenerator.generateKey();
        return new String(Hex.encodeHex(secretKey.getEncoded()));
    }

    /**
     * 根据16进制生成的密钥字符串和算法还原密钥
     *
     * @param keyStr
     * @return
     */
    public static SecretKey restoreKey(String keyStr, String algorithm) throws DecoderException {
        byte[] bytesKey = Hex.decodeHex(keyStr);
        return new SecretKeySpec(bytesKey, algorithm);
    }

    /**
     * 根据算法生成16进制摘要
     * @param str
     * @param keyStr
     * @param algorithm
     * @return
     * @throws DecoderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static String encodeHex(String str,String keyStr, String algorithm) throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKey secretKey = restoreKey(keyStr, algorithm);
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);
        byte[] bytes = mac.doFinal(str.getBytes(StandardCharsets.UTF_8));
        return ByteTransfer.byteArrayTransfer2HexString(bytes);
    }
}
