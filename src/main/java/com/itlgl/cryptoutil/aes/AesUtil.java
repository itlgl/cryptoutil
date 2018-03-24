package com.itlgl.cryptoutil.aes;

import com.itlgl.java.util.ByteUtil;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class AesUtil {
    public static void main(String[] args) throws Exception {
        {
            byte[] input = ByteUtil.fromHex("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
            byte[] key = ByteUtil.fromHex("636869636b656e207465726979616b69");
            BufferedBlockCipher engine = new CTSBlockCipher(new CBCBlockCipher(new AESEngine()));
            engine.init(true, new ParametersWithIV(new KeyParameter(key), new byte[16]));
            byte[] out = new byte[input.length];
            int len = engine.processBytes(input, 0, input.length, out, 0);
            engine.doFinal(out, len);

            System.out.println("out=" + ByteUtil.toHex(out));
        }
        {
            byte[] input = ByteUtil.fromHex("01020304050607080102030405060708");
            byte[] key = ByteUtil.fromHex("0102030405060708");
            BufferedBlockCipher engine = new CTSBlockCipher(new CBCBlockCipher(new DESEngine()));
            engine.init(true, new ParametersWithIV(new KeyParameter(key), new byte[8]));
            byte[] out = new byte[input.length];
            int len = engine.processBytes(input, 0, input.length, out, 0);
            System.out.println("len=" + len);
            System.out.println("out des before final=" + ByteUtil.toHex(out));
            engine.doFinal(out, len);

            System.out.println("out des=" + ByteUtil.toHex(out));
        }

        {
            byte[] input = ByteUtil.fromHex("0102030405060708");
            byte[] key = ByteUtil.fromHex("0102030405060708");
            BufferedBlockCipher engine = new CTSBlockCipher(new DESEngine());
            engine.init(true, new KeyParameter(key));
            byte[] out = new byte[input.length];
            int len = engine.processBytes(input, 0, input.length, out, 0);
            engine.doFinal(out, len);

            System.out.println("out des ddd=" + ByteUtil.toHex(out));
        }
    }
}
