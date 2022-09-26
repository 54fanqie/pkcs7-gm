package com.stamp.platform.bean.bc.outputStream;

import com.stamp.platform.util.HexUtil;
import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @description: SWDigestOutputStream
 * @date: 2022/9/8 11:37
 * @author: fanqie
 */
public class ELS_BcDigestOutputStream extends OutputStream {
    private Digest dig;

    public ELS_BcDigestOutputStream(Digest dig) {
        this.dig = dig;
    }

    @Override
    public void write(byte[] bytes, int off, int len)
            throws IOException {
        System.out.println("DigestOutputStream设置原文：" + HexUtil.byteToHex(bytes));
        dig.update(bytes, off, len);

    }

    @Override
    public void write(byte[] bytes)
            throws IOException {
        System.out.println("DigestOutputStream设置原文：" + HexUtil.byteToHex(bytes));
        dig.update(bytes, 0, bytes.length);

    }

    @Override
    public void write(int b)
            throws IOException {
        dig.update((byte) b);
    }

    public byte[] getDigest() {
        byte[] d = new byte[dig.getDigestSize()];
        dig.doFinal(d, 0);
        System.out.println("DigestOutputStream获取摘要值 ：" + HexUtil.byteToHex(d) + " 长度  " + d.length);
        return d;
    }
}
