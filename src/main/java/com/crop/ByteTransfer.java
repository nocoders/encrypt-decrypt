package com.crop;

import org.bouncycastle.util.encoders.Hex;

/**
 * @author linmeng
 * @date 2022/5/15 15:08
 */

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
