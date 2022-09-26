package com.stamp.platform.bean.pkcs7;

import com.stamp.platform.bean.GMPKCSObjectIdentifiers;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Enumeration;

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
 * @description: SignerInfoExt
 * @date: 2022/9/23 15:10
 * @author: fanqie
 */
public class SignerInfoExt extends SignerInfo {
    private static final Logger logger = LoggerFactory.getLogger(SignerInfoExt.class);
    /**
     * 用户认证属性集合元素
     * 这个元素是可选的，但如果contentInfo 的 ContentType不是数据内容（PKCS7 DATA）类型时，
     * 这个元素必须有。
     * 如果这个元素存在，它至少得有两个子元素：原文类型属性和原文摘要属性。
     * 示例代码里设置了三个属性：原文类型属性、时间属性和原文摘要属性。
     */
    byte[] authData;

    /**
     * 用户认证属性集合元素中  原文摘要
     * 这个元素是可选的，但如果contentInfo 的 ContentType不是数据内容（PKCS7 DATA）类型时，
     * 这个元素必须有。
     * 如果这个元素存在，它至少得有两个子元素：原文类型属性和原文摘要属性。
     * 示例代码里设置了三个属性：原文类型属性、时间属性和原文摘要属性。
     */
    byte[] plantDigestData;

    /**
     * 签名值
     * 根据PKCS#7标准，如果没有authenticatedAttributes元素，这里的摘要指原文的摘要；
     * 否则就是authenticatedAttributes的摘要，这也是authenticatedAttributes名称的由来
     */
    byte[] signature;


    public SignerInfoExt(ASN1Integer version, IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier digAlgorithm, ASN1Set authenticatedAttributes, AlgorithmIdentifier digEncryptionAlgorithm, ASN1OctetString encryptedDigest, ASN1Set unauthenticatedAttributes) {
        super(version, issuerAndSerialNumber, digAlgorithm, authenticatedAttributes, digEncryptionAlgorithm, encryptedDigest, unauthenticatedAttributes);
    }

    public SignerInfoExt(ASN1Sequence seq) {
        super(seq);
    }


    public static SignerInfoExt getInstance(Object var0) {
        if (var0 instanceof SignerInfoExt) {
            return (SignerInfoExt) var0;
        } else {
            return var0 != null ? new SignerInfoExt(ASN1Sequence.getInstance(var0)) : null;
        }
    }

    public byte[] getAuthData() {
        try {
            return super.getAuthenticatedAttributes().getEncoded();
        } catch (IOException e) {
            logger.error("认证属性集合解析字节失败" + e);
            return null;
        }
    }

    public byte[] getPlantDigestData() {
        //messageDigest 原文摘要
        if (plantDigestData !=null  && plantDigestData.length >0){
            return plantDigestData;
        }
        ASN1Set authenticatedAttributes = super.getAuthenticatedAttributes();
        Enumeration enumeration = authenticatedAttributes.getObjects();
        while (enumeration.hasMoreElements()) {
            Attribute attribute = Attribute.getInstance(enumeration);
            if (attribute.getAttrType().getId().equals(GMPKCSObjectIdentifiers.authenticate_messageDigest.getId())) {
                ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) attribute.getAttrValues().getObjectAt(0);
                try {
                    plantDigestData = objectIdentifier.getEncoded();
                    return plantDigestData;
                } catch (IOException e) {
                    logger.error("解析认证属性集合中原文摘要数据失败" + e);
                    return null;
                }
            }
        }
        return null;
    }

    public byte[] getSignature() {
        return super.getEncryptedDigest().getOctets();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return super.toASN1Primitive();
    }
}
