package com.itlgl.cryptoutil.aes;

import com.itlgl.java.util.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

public class AESUtilTest {
    @Test
    public void testAes128Ecb() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] encryptResult = ByteUtil.fromHex("0A940BB5416EF045F1C39458C653EA5A0A940BB5416EF045F1C39458C653EA5A");

        byte[] result1 = AESUtil.aes128Ecb(key, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes128Ecb(key, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testAes192Ecb() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f0001020304050607");
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f0001020304050607000102030405060708090a0b0c0d0e0f0001020304050607");
        byte[] encryptResult = ByteUtil.fromHex("365050DBBEC4AF9AACE191DAB1977E07EB39780E4E9BA53CD4FE04DAB95E8A178545FD57C1B0CCFD6D458CFDBFBA7216");

        byte[] result1 = AESUtil.aes192Ecb(key, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes192Ecb(key, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testAes256Ecb() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] encryptResult = ByteUtil.fromHex("737D7012DE2B424F76877A9F0255CC22737D7012DE2B424F76877A9F0255CC22737D7012DE2B424F76877A9F0255CC22737D7012DE2B424F76877A9F0255CC22");

        byte[] result1 = AESUtil.aes256Ecb(key, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes256Ecb(key, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testAes128Cbc() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] icv = new byte[16];
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] encryptResult = ByteUtil.fromHex("0A940BB5416EF045F1C39458C653EA5AD15C69180D25B041CF7A8C2CB98B9B3F");

        byte[] result1 = AESUtil.aes128Cbc(key, icv, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes128Cbc(key, icv, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testAes192Cbc() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f0001020304050607");
        byte[] icv = new byte[16];
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f0001020304050607000102030405060708090a0b0c0d0e0f0001020304050607");
        byte[] encryptResult = ByteUtil.fromHex("365050DBBEC4AF9AACE191DAB1977E07ED5CC4E58C7B5C6B0977077363920B1C469A3D7959BD10BB11A9FDED2E22CED1");

        byte[] result1 = AESUtil.aes192Cbc(key, icv, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes192Cbc(key, icv, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }

    @Test
    public void testAes256Cbc() throws AESException {
        byte[] key = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] icv = new byte[16];
        byte[] src = ByteUtil.fromHex("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
        byte[] encryptResult = ByteUtil.fromHex("737D7012DE2B424F76877A9F0255CC22AABEDAB46833F0232FBF3C7FD040F71B22BFDACC1A89297824F02CAE65452D76FC92338759019C1FEB51D28D7D13C277");

        byte[] result1 = AESUtil.aes256Cbc(key, icv, src, true);
        Assert.assertArrayEquals(encryptResult, result1);

        byte[] result2 = AESUtil.aes256Cbc(key, icv, encryptResult, false);
        Assert.assertArrayEquals(src, result2);
    }
}
