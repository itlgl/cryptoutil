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

    @Test
    public void testDesEdeEcb() throws DesException {
        byte[] key = ByteUtil.fromHex("010203040506070808070605040302010102030405060708");
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("74D46E87794D042274D46E87794D0422");

        byte[] result1 = DesUtil.desEdeEcb(key, src, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desEdeEcb(key, encrypResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testDesEeeEcb() throws DesException {
        byte[] key = ByteUtil.fromHex("010203040506070808070605040302010102030405060708");
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("9BD05B6CAF497B809BD05B6CAF497B80");

        byte[] result1 = DesUtil.desEeeEcb(key, src, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desEeeEcb(key, encrypResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testDesEdeCbc() throws DesException {
        byte[] key = ByteUtil.fromHex("010203040506070808070605040302010102030405060708");
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] icv = ByteUtil.fromHex("0102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("46345C8EEBDC745C2AFA8116541775BF");

        byte[] result1 = DesUtil.desEdeCbc(key, src, icv, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desEdeCbc(key, encrypResult, icv, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testDesEeeCbc() throws DesException {
        byte[] key = ByteUtil.fromHex("010203040506070808070605040302010102030405060708");
        byte[] src = ByteUtil.fromHex("01020304050607080102030405060708");
        byte[] icv = ByteUtil.fromHex("0102030405060708");
        byte[] encrypResult = ByteUtil.fromHex("E72B25AB138C9B282DE4DC6CCAA68E5D");

        byte[] result1 = DesUtil.desEeeCbc(key, src, icv, true);
        Assert.assertArrayEquals(encrypResult, result1);

        byte[] result2 = DesUtil.desEeeCbc(key, encrypResult, icv, false);
        Assert.assertArrayEquals(src, result2);
    }
}
