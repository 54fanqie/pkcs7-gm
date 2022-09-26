package com.test.bean;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;
import java.util.List;


/**
 * 签名者信息
 * SignerInfos：=Set of SignerInfo
 * SignerInfo::= SEQUENCE {
 * version Version, 首先是版本号属性，也是固定为1.
 * issuerAndSerialNumber    IssuerAndSerialNumber,  签名证书的签发者标识及序列号
 * digestAlgorithm          DigestAlgorithmIdentifier,  摘要算法标识
 * authenticated           Attributes[0] IMPLICIT Attributes OPTIONAL,  做用户认证属性集合元素
 * digestEncryption        AlgorithmDigestEncryptionAlgorithmIdentifier,
 * encryptedDigest         EncryptedDigest,
 * unauthenticated         Attributes[1] IMPLICIT Attributes OPTIONAL 这个元素的定义与authenticatedAttributes一致，区别在于它不参与签名。所以一般用的很少。不过要注意，如果构造这个元素，它在SignerInfo里的tag值应该是TAG_OPT+1
 * }
 *
 * @description: SignerInfo
 * @date: 2022/8/24 17:54
 * @author: fanqie
 */
public class SignerInfo extends ASN1Object {
    /**
     * 首先是版本号属性，也是固定为1.
     */
    ASN1Integer version;


    /**
     * 签名证书的签发者标识及序列号
     */
    IssuerAndSerialNumber issuerAndSerialNumber;


    /**
     * 摘要算法标识，这里要与digestAlgorithms里的某一元素一致
     */
    AlgorithmIdentifier digestAlgorithm;


    /**
     * 用户认证属性集合元素
     * 这个元素是可选的，但如果contentInfo 的 ContentType不是数据内容（PKCS7 DATA）类型时，
     * 这个元素必须有。
     * 如果这个元素存在，它至少得有两个子元素：原文类型属性和原文摘要属性。
     * 示例代码里设置了三个属性：原文类型属性、时间属性和原文摘要属性。
     */
    ASN1Set authenticatedAttributes;
    List<Attribute> attributeList;

    /**
     * 签名算法属性定义，与摘要算法一致
     */
    AlgorithmIdentifier digestEncryptionAlgorithm;


    /**
     * 加密的摘要，也就是签名
     * 根据PKCS#7标准，如果没有authenticatedAttributes元素，这里的摘要指原文的摘要；
     * 否则就是authenticatedAttributes的摘要，这也是authenticatedAttributes名称的由来
     */
    ASN1OctetString encryptedDigest;


    /**
     * 用户认证属性集合元素
     * 这个元素是可选的
     * 这个元素的定义与authenticatedAttributes一致，
     * 区别在于它不参与签名。所以一般用的很少。不过要注意，如果构造这个元素，它在SignerInfo里的tag值应该是TAG_OPT+1
     */
    ASN1Set unauthenticatedAttributes;
    List<Attribute> unAttributeList;


    public static SignerInfo getInstance(Object var0) {
        if (var0 instanceof SignerInfo) {
            return (SignerInfo) var0;
        } else {
            return var0 != null ? new SignerInfo(ASN1Sequence.getInstance(var0)) : null;
        }
    }

    public SignerInfo(IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier digestAlgorithm, ASN1Set authenticatedAttributes, AlgorithmIdentifier digestEncryptionAlgorithm, ASN1OctetString encryptedDigest, ASN1Set unauthenticatedAttributes) {
        this.version = new ASN1Integer(1L);
        this.issuerAndSerialNumber = issuerAndSerialNumber;
        this.digestAlgorithm = digestAlgorithm;
        this.authenticatedAttributes = authenticatedAttributes;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
        this.unauthenticatedAttributes = unauthenticatedAttributes;
    }


    public SignerInfo(ASN1Sequence var1) {
        Enumeration var2 = var1.getObjects();
        this.version = (ASN1Integer) var2.nextElement();
        Object var0 = var2.nextElement();
        this.issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(var0);
        this.digestAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
        Object var3 = var2.nextElement();
        if (var3 instanceof ASN1TaggedObject) {
            this.authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject) var3, false);
            this.digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var2.nextElement());
        } else {
            this.authenticatedAttributes = null;
            this.digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(var3);
        }

        this.encryptedDigest = DEROctetString.getInstance(var2.nextElement());
        if (var2.hasMoreElements()) {
            this.unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject) var2.nextElement(), false);
        } else {
            this.unauthenticatedAttributes = null;
        }

    }


    public ASN1Integer getVersion() {
        return this.version;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    public List<Attribute> getAttributeList() {
        return attributeList;
    }

    public List<Attribute> getUnAttributeList() {
        return unAttributeList;
    }

    public ASN1Set getAuthenticatedAttributes() {
        return this.authenticatedAttributes;
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public ASN1OctetString getEncryptedDigest() {
        return this.encryptedDigest;
    }

    public AlgorithmIdentifier getDigestEncryptionAlgorithm() {
        return this.digestEncryptionAlgorithm;
    }

    public ASN1Set getUnauthenticatedAttributes() {
        return this.unauthenticatedAttributes;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector(7);
        var1.add(this.version);
        var1.add(this.issuerAndSerialNumber);
        var1.add(this.digestAlgorithm);
        if (this.authenticatedAttributes != null) {
            var1.add(new DERTaggedObject(false, 0, this.authenticatedAttributes));
        }

        var1.add(this.digestEncryptionAlgorithm);
        var1.add(this.encryptedDigest);
        if (this.unauthenticatedAttributes != null) {
            var1.add(new DERTaggedObject(false, 1, this.unauthenticatedAttributes));
        }

        return new BERSequence(var1);
    }
}
