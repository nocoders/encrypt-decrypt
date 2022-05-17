package com.crop;

import com.crop.ByteTransfer;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @author linmeng
 * @date 2022/5/15 15:06
 */

public class SHAUtil {
    /**
     * jdk SHA1
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String jdkSHA1(String str) throws NoSuchAlgorithmException {
        return shaEncode(str, "SHA");
    }
    /**
     * jdk SHA-224
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String jdkSHA224(String str) throws NoSuchAlgorithmException {
        return shaEncode(str, "SHA-224");
    }
    /**
     * jdk SHA-256
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String jdkSHA256(String str) throws NoSuchAlgorithmException {

        return shaEncode(str, "SHA-256");
    }
     /**
     * jdk SHA-384
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String jdkSHA384(String str) throws NoSuchAlgorithmException {

        return shaEncode(str, "SHA-384");
    }
    /**
     * jdk SHA-512
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String jdkSHA512(String str) throws NoSuchAlgorithmException {
        return shaEncode(str, "SHA-512");
    }

    public static String shaEncode(String str, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);

        return ByteTransfer.byteArrayTransfer2HexString(md.digest(str.getBytes(StandardCharsets.UTF_8)));
    }
    /**
     * codec SHA1
     * @param str
     * @return
     */
    public static String codecSHA1(String str) {
        return DigestUtils.sha1Hex(str);
    }
    /**
     * codec SHA-224
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String bouncyCastleSha224(String str) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest md = MessageDigest.getInstance("SHA-224");
        return ByteTransfer.byteArrayTransfer2HexString(md.digest(str.getBytes(StandardCharsets.UTF_8)));
    }
    /**
     * codec SHA-256
     * @param str
     * @return
     */
    public static String codecSHA256(String str) {
        return DigestUtils.sha256Hex(str);
    }

    /**
     * codec SHA3-384
     * @param str
     * @return
     */
    public static String codecSHA384(String str) {
        return DigestUtils.sha3_384Hex(str);
    }

    /**
     * codec SHA-512
     * @param str
     * @return
     */
    public static String codecSHA512(String str) {
        return DigestUtils.sha512Hex(str);
    }
    /**
     * codec SHA3-224
     * @param str
     * @return
     */
    public static String codecSHA3224(String str) {
        return DigestUtils.sha3_224Hex(str);
    }

    /**
     * codec SHA3-256
     * @param str
     * @return
     */
    public static String codecSHA3256(String str) {
        return DigestUtils.sha3_256Hex(str);
    }

    /**
     * codec SHA3-384
     * @param str
     * @return
     */
    public static String codecSHA3384(String str) {
        return DigestUtils.sha3_384Hex(str);
    }
    /**
     * codec SHA3-512
     * @param str
     * @return
     */
    public static String codecSHA3512(String str) {
        return DigestUtils.sha3_512Hex(str);
    }
}
