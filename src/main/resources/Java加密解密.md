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

MAC算法结合了MD和SHA算法的优势，并加入密钥的支持，是一种更为安全的消息摘要算法。MAC算法分为两大系列，MD系列和SHA系列。MD系列包括HmacMD2、HmacMD4和HmacMD5三种算法，SHA系列有HmacSHA1、HmacSHA224、HmacSHA256、HmacSHA384和HmacSHA512五种算法。

JDK支持HmacMD5、HmacSHA1、HmacSHA256、HmacSHA384和HmacSHA512，Bouncy Castle支持HmacMD2、HmacMD4和HmacSHA224。

#### 实现

##### 公共方法

我提取出来三个公共方法，一个是生成密钥字符串的、一个是将密钥字符串转换成密钥对象的，最后一个是生成摘要字符串的。为了方便保存和使用，我们将密钥和摘要字节数组转为16进制字符串。

```
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
```

##### 各算法实现

简单，粗暴

```
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
```

### 其他消息摘要算法

还有一些消息摘要算法，目前不作介绍，后续新开一篇文章进行介绍

## 对称加密算法

对称加密算法是现在应用范围最广，使用频率最高的加密算法。当我们想对一些私密数据进行密码保护时，就可以用对称加密，使用密钥对数据进行加密、解密。目前可通过Java语言实现的对称加密算法有20多种，典型的对称加密主要是这四种：DES、DESede、AES和IDEA，接下来我们就将这四种加密算法逐个介绍。

### DES算法

开篇说明：DES目前已经被破解，在工作中用处不大，可以跳过，有兴趣的同学可以看下

#### 工作流程

1. 由消息发送方构建密钥并公布给消息接收方
2. 消息发送方使用密钥对数据加密，然后将加密数据发送
3. 消息接收方将接收到的数据进行解密

流程很简单，JDK支持56位密钥长度，作为补充，Bouncy Castle提供64位密钥长度，相较于JDK安全性更高，并且补充了多种填充方式。

#### 代码实现

加密算法的代码实现基本上就是几个方法，是密钥字符串的生成、密钥字符串转密钥对象、加密和解密。接下来我们一个个的编写各个方法

```
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * @author linmeng
 * @date 2022/5/22 22:43
 */

public class DESUtil {

    /* 密钥算法*/
    private static final String KEY_ALGORITHM = "DES";
    /*加密解密算法/工作方式/填充模式*/
    private static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * 根据算法生成密钥
     * jdk 和 Bouncy Castle 密钥生成代码不一样，根据条件执行不同代码
     * @param isBouncyCastle 是否生成Bouncy Castle
     * @return
     */
    public static String initKey(Boolean isBouncyCastle) throws Exception {
        KeyGenerator keyGenerator;
        if (isBouncyCastle){
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM,"BC");
            keyGenerator.init(64);
        }else {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(56);
        }
        SecretKey secretKey = keyGenerator.generateKey();
        return new String(Hex.encodeHex(secretKey.getEncoded()));
    }

    /**
     * 根据16进制生成的密钥字符串和算法还原密钥
     *
     * @param keyStr
     * @return
     */
    public static SecretKey restoreKey(String keyStr) throws Exception {
        byte[] bytesKey = Hex.decodeHex(keyStr);
        // 密钥材料实例化
        DESKeySpec keySpec = new DESKeySpec(bytesKey);
        // 密钥工厂实例化
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        // 密钥实例化
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);

        return secretKey;
    }

    /**
     * 生成Base加密字符串
     * @param str
     * @param keyStr
     * @return
     */
    public static String encrypt(String str,String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);

        return Base64.encodeBase64String(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 对加密数据进行解密
     * @param message 已加密数据
     * @param keyStr 密钥字符串
     * @return 解密数据
     */
    public static String decrypt(String message,String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE,secretKey);

        return new String(cipher.doFinal(Base64.decodeBase64(message)));
    }
}
```

### DESede

DES算法由于密钥长度偏短和迭代次数偏少使得安全性不够高，现在已经被淘汰，为了提高安全强度，有人提出了多重DES加密的方式，有二重、三重和四重等几种加密方式，目前使用的相对较多的是三重DES，也就是我们要说的DESede。DESede通过增加迭代次数提高了安全性，但是也造成了处理时间过慢、密钥计算时间加长和加密效率不高等问题。个人不太建议使用。

JDK和Bouncy Castle都提供了DESede的实现，JDK的密钥长度支持112位和168位，Bouncy Castle支持密钥长度128位和192位。

#### 实现

代码实现通DES大同小异，只有密钥材料实例化的时候使用的DESedeKeySpec对象不一样

```

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * @author linmeng
 * @date 2022/5/22 22:43
 */

public class DESedeUtil {

    /* 密钥算法*/
    private static final String KEY_ALGORITHM = "DESede";
    /*加密解密算法/工作方式/填充模式*/
    private static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * 根据算法生成密钥
     * jdk 和 Bouncy Castle 密钥生成代码不一样，根据条件执行不同代码
     * @param isBouncyCastle 是否生成Bouncy Castle
     * @return
     */
    public static String initKey(Boolean isBouncyCastle) throws Exception {
        KeyGenerator keyGenerator;
        if (isBouncyCastle){
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM,"BC");
            keyGenerator.init(168);
        }else {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(192);
        }
        SecretKey secretKey = keyGenerator.generateKey();
        return new String(Hex.encodeHex(secretKey.getEncoded()));
    }

    /**
     * 根据16进制生成的密钥字符串和算法还原密钥
     *
     * @param keyStr
     * @return
     */
    public static SecretKey restoreKey(String keyStr) throws Exception {
        byte[] bytesKey = Hex.decodeHex(keyStr);
        // 密钥材料实例化
        DESedeKeySpec keySpec = new DESedeKeySpec(bytesKey);
        // 密钥工厂实例化
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        // 密钥实例化
        return secretKeyFactory.generateSecret(keySpec);
    }

    /**
     * 生成Base加密字符串
     * @param str
     * @param keyStr
     * @return
     */
    public static String encrypt(String str,String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);

        return Base64.encodeBase64String(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 对加密数据进行解密
     * @param message 已加密数据
     * @param keyStr 密钥字符串
     * @return 解密数据
     */
    public static String decrypt(String message,String keyStr) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        // 初始化
        cipher.init(Cipher.DECRYPT_MODE,secretKey);

        return new String(cipher.doFinal(Base64.decodeBase64(message)));
    }
}
```

### AES

由于DES出现了算法漏洞，DESede加密效率低下，于是出现了AES算法，他的效率比DESede快，并且通DESede一样安全，能够有效抵御针对DES算法的所有攻击。

#### 实现

```

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * @author linmeng
 * @date 2022/5/22 22:43
 */

public class AESUtil {

    /* 密钥算法*/
    private static final String KEY_ALGORITHM = "AES";
    /*加密解密算法/工作方式/填充模式*/
    // JDK 支持PKCS5Padding填充模式
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    // Bouncy Castle支持PKCS7Padding填充模式
    private static final String CIPHER_BC_ALGORITHM = "AES/ECB/PKCS7Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 根据算法生成密钥
     * jdk 和 Bouncy Castle 密钥生成代码不一样，根据条件执行不同代码
     *
     * @param isBouncyCastle 是否生成Bouncy Castle
     * @return
     */
    public static String initKey(Boolean isBouncyCastle) throws Exception {
        KeyGenerator keyGenerator;
        //AES 要求密钥长度为128位，192位，256位
        if (isBouncyCastle) {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, "BC");
            keyGenerator.init(256);
        } else {
            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(256);
        }
        SecretKey secretKey = keyGenerator.generateKey();
        return new String(Hex.encodeHex(secretKey.getEncoded()));
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
    public static String encrypt(String str, String keyStr, Boolean isBouncyCastle) throws Exception {
        SecretKey secretKey = restoreKey(keyStr);
        //  实例化
        Cipher cipher = Cipher.getInstance(isBouncyCastle ? CIPHER_BC_ALGORITHM : CIPHER_ALGORITHM);
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
```

#### 	

## 非对称加密算法

## 数字签名算法





## 参考链接

[Java加密和解密的艺术](https://baike.baidu.com/item/Java%E5%8A%A0%E5%AF%86%E4%B8%8E%E8%A7%A3%E5%AF%86%E7%9A%84%E8%89%BA%E6%9C%AF/2380797?fr=aladdin)

[非对称加密算法 (RSA、DSA）概述](https://www.jianshu.com/p/86fe93b9af9b)

[让你彻底理解Base64算法](https://blog.csdn.net/shusheng0007/article/details/118220299)

[一文搞懂单向散列加密：MD5、SHA-1、SHA-2、SHA-3](