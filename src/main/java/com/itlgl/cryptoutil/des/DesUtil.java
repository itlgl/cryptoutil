package com.itlgl.cryptoutil.des;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

public class DesUtil {
    private static final DESEngine DES_ENGINE = new DESEngine();

    /*
     * des的加解密
     * key和src的长度必须是8字节
     * 返回的结果也是8字节
     */
    protected static void desBlockFunc(byte[] key, byte[] src, int inOff, byte[] result, int outOff, boolean encrypting) {
        DES_ENGINE.init(encrypting, new KeyParameter(key));
        DES_ENGINE.processBlock(src, inOff, result, outOff);
    }

    private static final void xor(byte[] b1, byte[] b2, byte[] result, int length) throws DesException {
        if(b1 == null || b2 == null || result == null ||
                b1.length < length || b2.length < length || result.length < length) {
            throw new DesException("param error");
        }
        for(int i = 0; i < length; i++) {
            result[i] = (byte) ((b1[i] ^ b2[i]) & 0xff);
        }
    }

    public static final byte[] desEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
        if(key == null || key.length != 8) {
            throw new DesException("Des key should be 8 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("Des src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("Des src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            desBlockFunc(key, src, i * 8, result, i * 8, encrypting);
        }
        return result;
    }

    public static final byte[] desCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
        if(key == null || key.length != 8) {
            throw new DesException("Des key should be 8 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("Des src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("Des src length should be be an integer multiple of 8");
        }
        if(icv == null || icv.length != 8) {
            throw new DesException("Des icv should be 8 bytes");
        }
        byte[] result = new byte[src.length];
        byte[] icvTem = Arrays.copyOfRange(icv, 0, 8);
        byte[] block = new byte[8];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            if(encrypting) {
                // 加密时，先异或，再加密
                System.arraycopy(src, i * 8, block, 0, 8);
                for(int j = 0; j < 8; j++) {
                    block[j] = (byte) ((block[j] ^ icvTem[j]) & 0xff);
                }
                desBlockFunc(key, block, 0, result, i * 8, true);
                System.arraycopy(result, i * 8, icvTem, 0, 8);
            } else {
                // 解密时，先解密，再异或
                desBlockFunc(key, src, i * 8, block, 0, false);
                for(int j = 0; j < 8; j++) {
                    block[j] = (byte) ((block[j] ^ icvTem[j]) & 0xff);
                }
                System.arraycopy(block, 0, result, i * 8, 8);
                // 将这一组的密文作为下一组解密后异或的icv
                System.arraycopy(src, i * 8, icvTem, 0, 8);
            }
        }
        return result;
    }
}
