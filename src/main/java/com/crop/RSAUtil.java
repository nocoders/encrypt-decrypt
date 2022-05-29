package com.crop;

import javafx.util.Pair;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author linmeng
 * @date 2022/5/29 21:16
 */

public class RSAUtil {
    /* 密钥算法*/
    private static final String KEY_ALGORITHM = "RSA";
    private static final Integer KEY_SIZE = 1024;


    /**
     * 根据算法生成密钥
     *
     * @return
     */
    public static Pair<String,String> initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        String PRIVATE_KEY = Hex.encodeHexString(keyPair.getPrivate().getEncoded());
        String PUBLIC_KEY = Hex.encodeHexString(keyPair.getPublic().getEncoded());
        return new Pair(PRIVATE_KEY, PUBLIC_KEY);
    }

    /**
     * 公钥生成
     *
     * @param keyStr
     * @return
     */
    public static PublicKey restorePublicKey(String keyStr) throws Exception {
        byte[] bytesKey = Hex.decodeHex(keyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytesKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);


        return keyFactory.generatePublic(keySpec);
    }
  /**
     * 私钥生成
     *
     * @param keyStr
     * @return
     */
    public static PrivateKey restorePrivateKey(String keyStr) throws Exception {
        byte[] bytesKey = Hex.decodeHex(keyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytesKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);


        return keyFactory.generatePrivate(keySpec);
    }


    public static String privateEncrypt(String str, String keyStr) throws Exception {
        PrivateKey privateKey = restorePrivateKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return Hex.encodeHexString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }

    public static String publicDecrypt(String message, String keyStr) throws Exception {
        byte[] decryptBytes = Hex.decodeHex(message);
        PublicKey publicKey = restorePublicKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(cipher.doFinal(decryptBytes));
    }


    public static String publicEncrypt(String str, String keyStr) throws Exception {
        PublicKey publicKey = restorePublicKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Hex.encodeHexString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }

    public static String privateDecrypt(String message, String keyStr) throws Exception {
        byte[] decodeBytes = Hex.decodeHex(message);
        PrivateKey privateKey = restorePrivateKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(decodeBytes));
    }
}
