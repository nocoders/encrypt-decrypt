# Java加密解密

本文介绍工作中能用到的加密算法以及加密方式使用场景和代码实现。相关代码在[github]( https://github.com/nocoders/encrypt-decrypt.git )上可以看到

JDK提供了大量的算法的实现，但是有一些算法的加密强度不够，有些算法没有提供相应的实现。Bouncy Castle和Codec两大开源组件包补充了JDK未提供的算法的实现以及较高的加密强度，我们可以引入两者相关依赖。

```
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
    <version>1.15</version>
</dependency>
```

## Base64

### Base64算法

为了解决非ASCII码字符的传输问题，将三个字符(24个字节）为一组，六个六个分开，每六个字节转为一个Base64字符，最后不够的用=代替。

#### 实现

Bouncy Castle 和Codec都提供了Base64算法的实现，代码也很简单。

```
// Bouncy Castle 提供
import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;

/**
 * Bouncy Castle  Base64算法实现
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
}
```

```
// codec提供
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

/**
 * Base64算法实现
 *  Bouncy Castle 和codec均有实现
 * @author linmeng
 * @date 2022/5/8 21:59
 */

public class Base64Util {
    /**
     * codec 加密
     * @param data
     * @return
     */
    public static String codecEncode(String data){

        return new String(Base64.encodeBase64(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * codec 加密
     * @param encodeStr
     * @return
     */
    public static String codecDecode(String encodeStr){

        return new String(Base64.decodeBase64(encodeStr),StandardCharsets.UTF_8);
    }
}
```

#### 测试方法

```
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
```

### URL Base64算法

根据URL相关要求，+、/是不允许出现在url中的，在URL Base64算法中，使用-和_替代了+和/。同时=作为url的参数分割符，也不允许出现，如果想实现定长的Base64编码串，=也需要对应的替代符号。Bouncy Castle 和codec两者对Url Base64的实现各不相同，Bouncy Castle使用了.作为填充符，codec则直接放弃了填充符，使用不定长Url Base64编码。

#### 实现

Bouncy Castle

```
import org.bouncycastle.util.encoders.UrlBase64;
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
```

codec

```
import org.apache.commons.codec.binary.Base64;
/**
     * codec url 加密
     * @param data
     * @return
     */
    public static String codecUrlEncode(String data){

        return new String(Base64.encodeBase64URLSafe(data.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * codec url 解密
     * @param encodeStr
     * @return
     */
    public static String codecUrlDecode(String encodeStr){

        return new String(Base64.decodeBase64(encodeStr.getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8);
    }
```

测试方法

```
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
```



## 消息摘要算法

消息摘要算法又称为散列算法，其核心在于散列函数的单向性。即核心在于通过散列函数只能获取对应的散列值，不可通过散列值推出其原始信息。消息摘要算法分三种，MD、SHA和MAC。

### MD算法

MD算法有MD2、MD3、MD4、MD5四种算法，这四种算法一步步改进来的，安全性也随之提高，本文章只使用MD5算法作为例子，其他算法基本相同，除了算法名称。目前MD5已经被攻破，不再是安全的。

JDK、Bouncy Castle 和codec都支持MD5，代码也比较简单。

#### 实现

```

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

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
    public static byte[] jdkMd5(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        return messageDigest.digest(str.getBytes(StandardCharsets.UTF_8));
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
```

### SHA算法

SHA算法是基于MD算法实现的，相较于MD算法，SHA算法摘要更长，安全性更高。

SHA算法分为SHA1算法、SHA2算法和SHA3算法。SHA1算法可对最大长度为264的字节信息做摘要处理得到一个160位的摘要信息，将160位摘要信息换为16进制，四位二进制转为一位16进制，得到40位字符串。SHA2算法痛SHA1算法相比，摘要信息更长，安全系数更高。SHA2算法根据生成摘要的长度不同，分为SHA-224、SHA-256、SHA-384和SHA-512四个算法。SHA1和SHA2使用的相同的基本算法，只不过SHA2安全性更高，现在没有被攻破，SHA3算法是一个全新的算法，同SHA1、SHA2不同。SHA3算法包括SHA3-224、SHA3-256、SHA3-384和SHA3-512。目前SHA2和SHA3算法是安全的，SHA1已经被破解。

#### 实现

JDK对支持SHA-1、SHA-224、SHA-256、SHA-384和SHA-512四种算法，JDK9开始支持SHA3算法，Codec支持所有算法，并且将其转成了16进制的字符串。

SHA算法都会生成二进制数组，提供一个将二进制数组转为16进制字符串的方法。

```
public class ByteTransfer {
    /**
     * 将字节数据转为16进制字符串
     * @param bytes
     * @return
     */
    public static String byteArrayTransfer2HexString(byte[] bytes){
        return new String(Hex.encode(bytes));
    }
}
```

##### jdk实现

各个算法除了算法名称外，实现方式基本一样，提取一个公共方法shaEncode。

```
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
```

##### codec实现

codec实现了各种算法，请看代码

```
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
```

### MAC算法

MAC算法结合了MD和SHA算法的优势，并加入密钥的支持，是一种更为安全的消息摘要算法。

MAC算法主要集合了MD和SHA两大消息摘要算法，MD系列有HmacMd2、HmacMd4和HmacMd5三种算法，SHA系列有HmacSha1、HmacSha224、HmacSha256、HmacSha384和HMacSha512五种算法。JDK 实现了

使用MAC算法主要分两步，构建密钥，获取摘要。

这个我写了三个公共方法：生成密钥字符串方法、还原密钥方法和获取摘要方法。

```
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
```



## 对称加密算法

## 非对称加密算法

## 数字签名算法





## 参考链接

[Java加密和解密的艺术](https://baike.baidu.com/item/Java%E5%8A%A0%E5%AF%86%E4%B8%8E%E8%A7%A3%E5%AF%86%E7%9A%84%E8%89%BA%E6%9C%AF/2380797?fr=aladdin)

[非对称加密算法 (RSA、DSA）概述](https://www.jianshu.com/p/86fe93b9af9b)

[让你彻底理解Base64算法](https://blog.csdn.net/shusheng0007/article/details/118220299)

[一文搞懂单向散列加密：MD5、SHA-1、SHA-2、SHA-3](https://baijiahao.baidu.com/s?id=1712156053788575917&wfr=spider&for=pc)