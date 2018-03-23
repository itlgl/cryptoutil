package com.itlgl.cryptoutil.des;

import java.util.Arrays;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import com.itlgl.java.util.ByteUtil;

public class Test {

    /*
     * des的加解密
     * key和src的长度必须是8字节
     * 返回的结果也是8字节
     */
    byte[] desBlockProcess(byte[] key, byte[] src, boolean encrypting) {
        byte[] result = new byte[8];
        DESEngine desEngine = new DESEngine();
        desEngine.init(encrypting, new KeyParameter(key));
        desEngine.processBlock(src, 0, result, 0);
        return result;
    }

    /*
     * des ede模式的加解密
     * key的长度为24字节，src的长度为8字节
     * 返回的结果是8字节
     *
     * 所谓ede就是加解加：
     * 1.取key的0-7字节对src加密得到result1
     * 2.取key的8-15字节对result1解密得到result2
     * 3.取key的16-23字节对result2加密得到result3，result3就是最终的加密结果
     *
     * 关于这个模式的延伸，如果src大于8字节怎么处理：
     * 1.如果src的长度大于8字节又不是8字节的整数倍，需要先使用padding算法将src补足到8字节整数倍，比如pkcs5padding
     * 2.如果src是8字节的整数倍，加密模式中多了两个关键词，DES ECB（电子密本方式）和DES CBC（密文分组链接方式）
     * 2.1 DES ECB（电子密本方式）其实非常简单，就是将数据按照8个字节一段进行DES加密或解密得到一段8个字节的密文或者明文，
     *     最后一段不足8个字节，按照需求补足8个字节进行计算，之后按照顺序将计算所得的数据连在一起即可，各段数据之间互不影响
     * 2.2 DES CBC（密文分组链接方式）有点麻烦，它的实现机制使加密的各段数据之间有了联系。其实现的机理如下：
     *     1）首先将数据按照8个字节一组进行分组得到D1D2......Dn（若数据不是8的整数倍，用指定的PADDING数据补位）
     *     2）第一组数据D1与初始化向量I异或后的结果进行DES加密得到第一组密C1（文初始化向量I为全零或者其他值）
     *     3）第二组数据D2与第一组的加密结果C1异或以后的结果进行DES加密，得到第二组密文C2
     *     4）之后的数据以此类推，得到Cn
     *     5）按顺序连为C1C2C3......Cn即为加密结果。
     * 2.3 ECB和CBC模式参考：http://blog.csdn.net/season_hangzhou/article/details/9228363
     * 3. 如果解密的话，就把上述过程反过来就可以了
     *
     */
    byte[] desEDEBlockProcess(byte[] key, byte[] src, boolean encrypting) {
        byte[] result = new byte[8];

        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);

        result = desBlockProcess(key1, src, encrypting);
        result = desBlockProcess(key2, result, !encrypting);
        result = desBlockProcess(key3, result, encrypting);

        return result;
    }

    /*
     * des eee模式的加解密
     * key的长度为24字节，src的长度为8字节
     * 返回的结果是8字节
     *
     * 所谓eee就是加加加：
     * 1.取key的0-7字节对src加密得到result1
     * 2.取key的8-15字节对result1加密得到result2
     * 3.取key的16-23字节对result2加密得到result3，result3就是最终的加密结果
     */
    byte[] desEEEBlockProcess(byte[] key, byte[] src, boolean encrypting) {
        byte[] result = new byte[8];

        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);

        result = desBlockProcess(key1, src, encrypting);
        result = desBlockProcess(key2, result, encrypting);
        result = desBlockProcess(key3, result, encrypting);

        return result;
    }

    /*
     * des ede ecb process
     * key的长度为24字节，src的长度为8字节的整数倍
     * 返回结果为src的长度
     */
    byte[] desEDEEcbProcess(byte[] key, byte[] src, boolean encrypting) {
        byte[] result = new byte[src.length];
        byte[] blockSrc = new byte[8];
        byte[] blockResult = null;
        for (int i = 0, len = src.length / 8; i < len; i++) {
            System.arraycopy(src, i * 8, blockSrc, 0, 8);
            blockResult = desEDEBlockProcess(key, blockSrc, encrypting);
            System.arraycopy(blockResult, 0, result, i * 8, 8);
        }
        return result;
    }

    byte[] desEEEEcbProcess(byte[] key, byte[] src, boolean encrypting) {
        byte[] result = new byte[src.length];
        byte[] blockSrc = new byte[8];
        byte[] blockResult = null;
        for (int i = 0, len = src.length / 8; i < len; i++) {
            System.arraycopy(src, i * 8, blockSrc, 0, 8);
            blockResult = desEEEBlockProcess(key, blockSrc, encrypting);
            System.arraycopy(blockResult, 0, result, i * 8, 8);
        }
        return result;
    }

    byte[] desEDECbcProcess(byte[] key, byte[] src, byte[] icv, boolean encrypting) {
        byte[] result = new byte[src.length];
        byte[] blockSrc = new byte[8];
        byte[] blockResult = null;
        byte[] icvTem = Arrays.copyOfRange(icv, 0, 8);
        for (int i = 0, len = src.length / 8; i < len; i++) {
            System.arraycopy(src, i * 8, blockSrc, 0, 8);
            for(int j = 0;j<8;j++) {
                blockSrc[j] = (byte) ((blockSrc[j] ^ icvTem[j]) & 0xff);
            }
            blockResult = desEDEBlockProcess(key, blockSrc, encrypting);
            System.arraycopy(blockResult, 0, icvTem, 0, 8);
            System.arraycopy(blockResult, 0, result, i * 8, 8);
        }
        return result;
    }

    byte[] desEEECbcProcess(byte[] key, byte[] src, byte[] icv, boolean encrypting) {
        byte[] result = new byte[src.length];
        byte[] blockSrc = new byte[8];
        byte[] blockResult = null;
        byte[] icvTem = Arrays.copyOfRange(icv, 0, 8);
        for (int i = 0, len = src.length / 8; i < len; i++) {
            System.arraycopy(src, i * 8, blockSrc, 0, 8);
            for(int j = 0;j<8;j++) {
                blockSrc[j] = (byte) ((blockSrc[j] ^ icvTem[j]) & 0xff);
            }
            blockResult = desEEEBlockProcess(key, blockSrc, encrypting);
            System.arraycopy(blockResult, 0, icvTem, 0, 8);
            System.arraycopy(blockResult, 0, result, i * 8, 8);
        }
        return result;
    }

    void test() {
        {
            // des encrypt
            byte[] key = ByteUtil.fromHex("0102030405060708");
            byte[] data = ByteUtil.fromHex("0102030405060708");
            byte[] result = desBlockProcess(key, data, true);
            System.out.println("des encrypt result=" + ByteUtil.toHex(result));
        }
        {
            // des decrypt
            byte[] key = ByteUtil.fromHex("0102030405060708");
            byte[] data = ByteUtil.fromHex("0102030405060708");
            byte[] result = desBlockProcess(key, data, false);
            System.out.println("des decrypt result=" + ByteUtil.toHex(result));
        }
        {
            // des ede block encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("0102030405060708");
            byte[] result = desEDEBlockProcess(key, data, true);
            System.out.println("des ede encrypt block result=" + ByteUtil.toHex(result));
        }
        {
            // des eee block encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("0102030405060708");
            byte[] result = desEEEBlockProcess(key, data, true);
            System.out.println("des eee decrypt block result=" + ByteUtil.toHex(result));
        }
        {
            // des ede ecb encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("01020304050607080102030405060708");
            byte[] result = desEDEEcbProcess(key, data, true);
            System.out.println("des ede decrypt result=" + ByteUtil.toHex(result));
        }
        {
            // des eee ecb encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("01020304050607080102030405060708");
            byte[] result = desEEEEcbProcess(key, data, true);
            System.out.println("des eee ecb decrypt result=" + ByteUtil.toHex(result));
        }
        {
            // des ede cbc encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("01020304050607080102030405060708");
            byte[] icv = ByteUtil.fromHex("0000000000000000");
            byte[] result = desEDECbcProcess(key, data, icv, true);
            System.out.println("des ede cbc decrypt result=" + ByteUtil.toHex(result));
        }
        {
            // des eee cbc encrypt
            byte[] key = ByteUtil.fromHex("010203040506070801020304050607080102030405060708");
            byte[] data = ByteUtil.fromHex("01020304050607080102030405060708");
            byte[] icv = ByteUtil.fromHex("0000000000000000");
            byte[] result = desEEECbcProcess(key, data, icv, true);
            System.out.println("des eee cbc decrypt result=" + ByteUtil.toHex(result));
        }
    }

    public static void main(String[] args) {
        Test test = new Test();
        test.test();
    }
}

