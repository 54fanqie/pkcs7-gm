package com.stamp.platform.bean.bc.outputStream;

import com.stamp.platform.util.HexUtil;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @description: BcSignerOutputStream
 * @date: 2022/9/6 15:53
 * @author: fanqie
 */
public class SwBcSignerOutputStream extends OutputStream
{
    private Signer sig;

    public SwBcSignerOutputStream(Signer sig)
    {
        this.sig = sig;
    }

    @Override
    public void write(byte[] bytes, int off, int len)
            throws IOException
    {
        System.out.println("SignerOutputStream类设置原文 ：" + HexUtil.byteToHex(bytes));
        sig.update(bytes, off, len);
    }

    @Override
    public void write(byte[] bytes)
            throws IOException
    {
        System.out.println("SignerOutputStream类设置原文 ：" + HexUtil.byteToHex(bytes));
        sig.update(bytes, 0, bytes.length);
    }

    @Override
    public void write(int b)
            throws IOException
    {
        sig.update((byte)b);
    }

    byte[] getSignature()
            throws CryptoException
    {
        return sig.generateSignature();
    }

    public boolean verify(byte[] expected)
    {
        return sig.verifySignature(expected);
    }
}
