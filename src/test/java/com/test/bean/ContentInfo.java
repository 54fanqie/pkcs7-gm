package com.test.bean;


import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * PKCS#7采用ASN.1语义描述，因此数字签名也需按照其通用语法标准封装成ContentInfo类型，通用的ContentInfo类型 其定义如下
    ContentInfo::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
    }
  ContentType::= OBJECT IDENTIFIER
 * @description: ContentInfo
 * @date: 2022/8/24 18:01
 * @author: fanqie
 */
public class ContentInfo extends ASN1Object {

    /**
     * 把PKCS#7 数字签名的标识赋值给它
     * contentType是OBJECT IDENTIFIER类型
     */
    ASN1ObjectIdentifier contentType;

    /**
     * OPTIONAL类型, 且content标识为0
     */
    ASN1Encodable content;

    private boolean       isBer = true;


    public  ContentInfo(ASN1ObjectIdentifier contentType,ASN1Encodable content) {
        this.contentType = contentType;
        this.content = content;
        isBer = content instanceof BERSequence;
    }

    public static ContentInfo getInstance(Object obj) {
        if (obj instanceof ContentInfo) {
            return (ContentInfo) obj;
        } else {
            return obj != null ? new ContentInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }


    public static ContentInfo getInstance(ASN1TaggedObject var0, boolean var1) {
        return getInstance(ASN1Sequence.getInstance(var0, var1));
    }

    public ContentInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();

        contentType = (ASN1ObjectIdentifier)e.nextElement();

        if (e.hasMoreElements())
        {
            content = ((ASN1TaggedObject)e.nextElement()).getObject();
        }

        isBer = seq instanceof BERSequence;
    }

    public ContentInfo(ASN1ObjectIdentifier var1, ASN1TaggedObject var2) {
        this.contentType = var1;
        this.content = var2;
    }


    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    public ASN1Encodable getContent() {
        return content;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector(2);
        var1.add(this.contentType);
        if (this.content != null) {
            var1.add(new BERTaggedObject(0, this.content));

            if (isBer)
            {
                return new BERSequence(var1);
            }
            else
            {
                return new DLSequence(var1);
            }
        }
        return new BERSequence(var1);
    }
}
