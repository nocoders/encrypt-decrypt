package com.crop;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.UrlBase64;

import java.nio.charset.StandardCharsets;

/**
 * Base64算法实现
 *  Bouncy Castle 和codec均有实现
 * @author linmeng
 * @date 2022/5/8 21:59
 */

public class Base64Util {

    /**
     * Bouncy Castle 加密
     * @param data
     * @return
     */
    public static String bouncyCastleEncode(String data){

        return new String(Base64.encode(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Bouncy Castle 加密
     * @param encodeStr
     * @return
     */
    public static String bouncyCastleDecode(String encodeStr){

        return new String(Base64.decode(encodeStr),StandardCharsets.UTF_8);
    }
    /**
     * codec 加密
     * @param data
     * @return
     */
    public static String codecEncode(String data){

        return new String(org.apache.commons.codec.binary.Base64.encodeBase64(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * codec 加密
     * @param encodeStr
     * @return
     */
    public static String codecDecode(String encodeStr){

        return new String(org.apache.commons.codec.binary.Base64.decodeBase64(encodeStr),StandardCharsets.UTF_8);
    }
    /**
     * Bouncy Castle url 加密
     * @param data
     * @return
     */
    public static String bouncyCastleUrlEncode(String data){

        return new String(UrlBase64.encode(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Bouncy Castle url 解密
     * @param encodeStr
     * @return
     */
    public static String bouncyCastleUrlDecode(String encodeStr){

        return new String(UrlBase64.decode(encodeStr),StandardCharsets.UTF_8);
    }
    /**
     * codec url 加密
     * @param data
     * @return
     */
    public static String codecUrlEncode(String data){

        return new String(org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * codec url 解密
     * @param encodeStr
     * @return
     */
    public static String codecUrlDecode(String encodeStr){

        return new String(org.apache.commons.codec.binary.Base64.decodeBase64(encodeStr.getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8);
    }
}
