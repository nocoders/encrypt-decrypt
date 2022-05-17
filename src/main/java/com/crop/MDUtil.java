package com.crop;

import com.crop.ByteTransfer;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;

/**
 * MD算法
 * @author linmeng
 * @date 2022/5/11 23:15
 */

public class MDUtil {
    /**
     * jdk提供md5实现
     * @param str
     * @throws NoSuchAlgorithmException
     */
    public static String jdkMd5(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        return ByteTransfer.byteArrayTransfer2HexString(messageDigest.digest(str.getBytes(StandardCharsets.UTF_8)));
    }
    /**
     * Bouncy Castle 提供md5实现
     * @param str
     * @throws NoSuchAlgorithmException
     */
    public static String bouncyCastleMd5(String str) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        return new String(Hex.encode(messageDigest.digest(str.getBytes(StandardCharsets.UTF_8))));
    }
    /**
     * codec 提供md5实现
     * @param str
     */
    public static String codecMd5(String str) {
        return DigestUtils.md5Hex(str);
    }
}
