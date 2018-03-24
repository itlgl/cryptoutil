package com.itlgl.cryptoutil.des;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class DesUtil {

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
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new DESEngine());
            engine.init(encrypting, new KeyParameter(key));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
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
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new CBCBlockCipher(new DESEngine()));
            engine.init(encrypting, new ParametersWithIV(new KeyParameter(key), icv));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
        }
        return result;
    }

    public static byte[] desEdeEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
        if(key == null || (key.length != 16 && key.length != 24)) {
            throw new DesException("DesEDE key should be 16 or 24 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEDE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEDE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new DESedeEngine());
            engine.init(encrypting, new KeyParameter(key));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
        }
        return result;
    }

    public static byte[] desEeeEcb(final byte[] key, final byte[] src, final boolean encrypting) throws DesException {
        if(key == null || (key.length != 16 && key.length != 24)) {
            throw new DesException("DesEDE key should be 16 or 24 bytes");
        }
        if(src == null || src.length == 0) {
            throw new DesException("DesEDE src should not be empty");
        }
        if(src.length % 8 != 0) {
            throw new DesException("DesEDE src length should be be an integer multiple of 8");
        }
        byte[] result = new byte[src.length];
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new DESeeeEngine());
            engine.init(encrypting, new KeyParameter(key));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
        }
        return result;
    }

    public static byte[] desEdeCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
        if(key == null || (key.length != 16 && key.length != 24)) {
            throw new DesException("DesEDE key should be 16 or 24 bytes");
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
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
            engine.init(encrypting, new ParametersWithIV(new KeyParameter(key), icv));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
        }
        return result;
    }

    public static byte[] desEeeCbc(final byte[] key, final byte[] src, final byte[] icv, final boolean encrypting) throws DesException {
        if(key == null || (key.length != 16 && key.length != 24)) {
            throw new DesException("DesEEE key should be 16 or 24 bytes");
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
        try {
            BufferedBlockCipher engine = new BufferedBlockCipher(new CBCBlockCipher(new DESeeeEngine()));
            engine.init(encrypting, new ParametersWithIV(new KeyParameter(key), icv));
            int len = engine.processBytes(src, 0, src.length, result, 0);
            engine.doFinal(result, len);
        } catch (InvalidCipherTextException e) {
            throw new DesException(e);
        }
        return result;
    }
}
