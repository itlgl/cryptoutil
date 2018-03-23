package com.itlgl.cryptoutil.des;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

public class DesUtil {
    private static final DESEngine DES_ENGINE = new DESEngine();

    /**
     * des的加解密
     * key和src的长度必须是8字节
     * 返回的结果也是8字节
     */
    private static void desBlockFunc(final byte[] key, final byte[] src, final int inOff, final byte[] result, final int outOff, final boolean encrypting) {
        DES_ENGINE.init(encrypting, new KeyParameter(key));
        DES_ENGINE.processBlock(src, inOff, result, outOff);
    }

    public static byte[] desEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
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

    public static byte[] desCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
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

    public static byte[] desEdeEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
        if(key == null || key.length != 24) {
            throw new DesException("DesEDE key should be 24 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEDE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEDE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        byte[] block1 = new byte[8], block2 = new byte[8];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            desBlockFunc(key1, src, i * 8, block1, 0, encrypting);
            desBlockFunc(key2, block1, 0, block2, 0, !encrypting);
            desBlockFunc(key3, block2, 0, result, i * 8, encrypting);
        }
        return result;
    }

    public static byte[] desEeeEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
        if(key == null || key.length != 24) {
            throw new DesException("DesEDE key should be 24 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEDE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEDE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        byte[] block1 = new byte[8], block2 = new byte[8];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            desBlockFunc(key1, src, i * 8, block1, 0, encrypting);
            desBlockFunc(key2, block1, 0, block2, 0, encrypting);
            desBlockFunc(key3, block2, 0, result, i * 8, encrypting);
        }
        return result;
    }

    public static byte[] desEdeCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
        if(key == null || key.length != 24) {
            throw new DesException("DesEDE key should be 24 bytes");
        }
        if(icv == null || icv.length != 8) {
            throw new DesException("DesEDE icv should be 8 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEDE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEDE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        byte[] block = new byte[8];
        byte[] icvTem = Arrays.copyOfRange(icv, 0, 8);
        byte[] block1 = new byte[8], block2 = new byte[8];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            if(encrypting) {
                // 加密时，先异或，再加密
                System.arraycopy(src, i * 8, block, 0, 8);
                for(int j = 0; j < 8; j++) {
                    block[j] = (byte) ((block[j] ^ icvTem[j]) & 0xff);
                }
                desBlockFunc(key1, block, 0, block1, 0, true);
                desBlockFunc(key2, block1, 0, block2, 0, false);
                desBlockFunc(key3, block2, 0, result, i * 8, true);
                System.arraycopy(result, i * 8, icvTem, 0, 8);
            } else {
                // 解密时，先解密，再异或
                desBlockFunc(key1, src, i * 8, block1, 0, false);
                desBlockFunc(key2, block1, 0, block2, 0, true);
                desBlockFunc(key3, block2, 0, block, 0, false);
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

    public static byte[] desEeeCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
        if(key == null || key.length != 24) {
            throw new DesException("DesEEE key should be 24 bytes");
        }
        if(icv == null || icv.length != 8) {
            throw new DesException("DesEEE icv should be 8 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEEE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEEE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        byte[] block = new byte[8];
        byte[] icvTem = Arrays.copyOfRange(icv, 0, 8);
        byte[] block1 = new byte[8], block2 = new byte[8];
        for(int i = 0, len = src.length / 8; i < len; i++) {
            if(encrypting) {
                // 加密时，先异或，再加密
                System.arraycopy(src, i * 8, block, 0, 8);
                for(int j = 0; j < 8; j++) {
                    block[j] = (byte) ((block[j] ^ icvTem[j]) & 0xff);
                }
                desBlockFunc(key1, block, 0, block1, 0, true);
                desBlockFunc(key2, block1, 0, block2, 0, true);
                desBlockFunc(key3, block2, 0, result, i * 8, true);
                System.arraycopy(result, i * 8, icvTem, 0, 8);
            } else {
                // 解密时，先解密，再异或
                desBlockFunc(key1, src, i * 8, block1, 0, false);
                desBlockFunc(key2, block1, 0, block2, 0, false);
                desBlockFunc(key3, block2, 0, block, 0, false);
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
