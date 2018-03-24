package com.itlgl.cryptoutil.aes;

import com.itlgl.cryptoutil.des.DESeeeEngine;
import com.itlgl.java.util.ByteUtil;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
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

    public static byte[] aes128Ecb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 16) {
            throw new AESException("AES key should be 16 bytes");
        }
        if(src == null || src.length % 16 != 0) {
            throw new AESException("AES src should be an integer multiple of 16");
        }
        return aesEcb(key, src, encrypting);
    }

    public static byte[] aes192Ecb(byte[] key, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 24) {
            throw new AESException("AES key should be 24 bytes");
        }
        if(src == null || src.length % 24 != 0) {
            throw new AESException("AES src should be an integer multiple of 24");
        }
        return aesEcb(key, src, encrypting);
    }

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

    public static byte[] aes128Cbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 16) {
            throw new AESException("AES key should be 16 bytes");
        }
        if(src == null || src.length % 16 != 0) {
            throw new AESException("AES src should be an integer multiple of 16");
        }
        return aesCbc(key, icv, src, encrypting);
    }

    public static byte[] aes192Cbc(byte[] key, byte[] icv, byte[] src, boolean encrypting) throws AESException {
        if(key == null || key.length != 24) {
            throw new AESException("AES key should be 24 bytes");
        }
        if(src == null || src.length % 24 != 0) {
            throw new AESException("AES src should be an integer multiple of 24");
        }
        return aesCbc(key, icv, src, encrypting);
    }

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
