package com.itlgl.cryptoutil.des;

import com.itlgl.java.util.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

public class DesUtilTest {
    @Test
    public void testDesEcb() throws DesException {
        byte[] key = ByteUtil.fromHex("0102030405060708");
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("77A7D6BCF57962B977A7D6BCF57962B9");

        byte[] result1 = DesUtil.desEcb(key, src, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desEcb(key, encrypResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testDesCbc() throws DesException {
        byte[] key = ByteUtil.fromHex("0102030405060708");
        byte[] icv = new byte[8];
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("77A7D6BCF57962B9DE153505D3821AFC");

        byte[] result1 = DesUtil.desCbc(key, src, icv, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desCbc(key, encrypResult, icv, false);
        Assert.assertArrayEquals(src, result2);
    }
}
