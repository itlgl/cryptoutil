package com.itlgl.cryptoutil.aes;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AESUtil {
    private static byte[] aesEcb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        byte[] result = new byte[src.length];
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new AESEngine());
            engine.init(encrypting, new KeyParameter(key));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new AESException(e);
        }
        return result;
    }

    /**
     * AES 128 ECB的加解密实现
     * @param key 16字节的密钥，密钥长度不对抛出异常
     * @param src 要加密或解密的数据，数据必须是8字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 错误是抛出异常
     */
    public static byte[] aes128Ecb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 16) {
            throw new AESException("AES key should be 16 bytes");
        }
        if(src == null || src.length % 16 != 0) {
            throw new AESException("AES src should be an integer multiple of 16");
        }
        return aesEcb(key, src, encrypting);
    }

    /**
     * AES 192 ECB的加解密算法实现
     * @param key 24字节密钥，密钥长度不对抛出异常
     * @param src 要加密或解密的数据，数据必须是8字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 错误是抛出异常
     */
    public static byte[] aes192Ecb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 24) {
            throw new AESException("AES key should be 24 bytes");
        }
        if(src == null || src.length % 24 != 0) {
            throw new AESException("AES src should be an integer multiple of 24");
        }
        return aesEcb(key, src, encrypting);
    }

    /**
     * AES 256 ECB的加解密算法实现
     * @param key 32字节密钥，密钥长度不对抛出异常
     * @param src 要加密或解密的数据，数据必须是8字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 错误是抛出异常
     */
    public static byte[] aes256Ecb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 32) {
            throw new AESException("AES key should be 32 bytes");
        }
        if(src == null || src.length % 32 != 0) {
            throw new AESException("AES src should be an integer multiple of 32");
        }
        return aesEcb(key, src, encrypting);
    }

    private static byte[] aesCbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        byte[] result = new byte[src.length];
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            engine.init(encrypting, new ParametersWithIV(new KeyParameter(key), icv));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new AESException(e);
        }
        return result;
    }

    /**
     * AES 128 CBC加解密算法的实现
     * @param key 16字节密钥
     * @param icv 16字节向量
     * @param src 要加密或解密的数据，数据必须是16字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 出现错误时抛出异常
     */
    public static byte[] aes128Cbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 16) {
            throw new AESException("AES key should be 16 bytes");
        }
        if(src == null || src.length % 16 != 0) {
            throw new AESException("AES src should be an integer multiple of 16");
        }
        return aesCbc(key, icv, src, encrypting);
    }

    /**
     * AES 192 CBC加解密算法的实现
     * @param key 24字节密钥
     * @param icv 16字节向量
     * @param src 要加密或解密的数据，数据必须是16字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 出现错误时抛出异常
     */
    public static byte[] aes192Cbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 24) {
            throw new AESException("AES key should be 24 bytes");
        }
        if(src == null || src.length % 24 != 0) {
            throw new AESException("AES src should be an integer multiple of 24");
        }
        return aesCbc(key, icv, src, encrypting);
    }

    /**
     * AES 256 CBC加解密算法的实现
     * @param key 32字节密钥
     * @param icv 16字节向量
     * @param src 要加密或解密的数据，数据必须是16字节的整数倍
     * @param encrypting 加密还是解密
     * @return 结果
     * @throws AESException 出现错误时抛出异常
     */
    public static byte[] aes256Cbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 32) {
            throw new AESException("AES key should be 32 bytes");
        }
        if(src == null || src.length % 32 != 0) {
            throw new AESException("AES src should be an integer multiple of 32");
        }
        return aesCbc(key, icv, src, encrypting);
    }
}
