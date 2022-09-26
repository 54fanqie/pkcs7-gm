package com.stamp.platform.bean.pkcs7;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

/**
 * @description: ProcessableContent
 * @date: 2022/8/31 14:36
 * @author: fanqie
 */
public class ProcessableContent {
    /**
     *
     *  contentInfo 中  ContentType 标识
     */
    private ASN1ObjectIdentifier type;
    /**
     * contentInfo 中 内容
     *
     */
    private byte[] content;

    private ASN1Encodable structure;

    public ProcessableContent(
            byte[]  content) throws IOException
    {
        this(CMSObjectIdentifiers.data, content);
    }

    public ProcessableContent(
            ASN1ObjectIdentifier type,
            byte[] content) throws IOException {
        this.type = type;
        this.content = content;
        this.structure =  ASN1OctetString.fromByteArray(content);
    }

    public ProcessableContent(
            ASN1ObjectIdentifier type,
            ASN1Encodable structure) {
        this.type = type;
        this.structure = structure;
    }
    public InputStream getInputStream()
    {
        return new ByteArrayInputStream(content);
    }

    public void write(OutputStream cOut)
            throws IOException
    {
        if (structure instanceof ASN1Sequence)
        {
            ASN1Sequence s = ASN1Sequence.getInstance(structure);

            for (Iterator it = s.iterator(); it.hasNext();)
            {
                ASN1Encodable enc = (ASN1Encodable)it.next();

                cOut.write(enc.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
        }
        else
        {
            byte[] encoded = structure.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            int index = 1;

            while ((encoded[index] & 0xff) > 127)
            {
                index++;
            }

            index++;
            // 给签名类 摘要类赋值
            cOut.write(encoded, index, encoded.length - index);
        }
    }
    public Object getContent()
    {
        return Arrays.clone(content);
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }


}
