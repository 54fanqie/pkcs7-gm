package com.stamp.platform.bean;

import com.stamp.platform.util.StringUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * 国密标准GM/T 0010定义的oid如下：
 */
public class GMPKCSObjectIdentifiers {
    /**
     * 仅支持RSA 与 GM算法
     */
    public static  String GM = "SM" ;
    public static  String RSA = "RSA";
    /**
     * SM2密码算法加密签名消息语法规范   pkcs-7的OID
     */
    public static ASN1ObjectIdentifier pkcs_7_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2").intern();
    /**
     * pkcs#7: 1.2.840.113549.1.7
     */
    public static ASN1ObjectIdentifier pkcs_7_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7").intern();

    /**
     * Data内容类型 ----->明文信息
     */
    public static ASN1ObjectIdentifier data_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1");
    /**
     * PKCS#7: 1.2.840.113549.1.7.1
     */
    public static ASN1ObjectIdentifier data_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.1").intern();


    /**
     * Signed-data内容类型 ----->数字签名
     */
    public static ASN1ObjectIdentifier signedData_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.2");
    /**
     * PKCS#7: 1.2.840.113549.1.7.2
     */
    public static ASN1ObjectIdentifier signedData_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.2").intern();

    /**
     * Enveloped-data 内容类型 ----->数字信封
     */
    public static ASN1ObjectIdentifier envelopedData_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.3");
    /**
     * PKCS#7: 1.2.840.113549.1.7.3
     */
    public static ASN1ObjectIdentifier envelopedData_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.3").intern();

    /**
     * Signed-and-enveloped-data 内容类型 ----->带签名的数字信封
     */
    public static ASN1ObjectIdentifier signedAndEnvelopedData_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.4");
    /**
     * PKCS#7: 1.2.840.113549.1.7.4
     */
    public static ASN1ObjectIdentifier signedAndEnvelopedData_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.4").intern();

    /**
     * Digested-data内容类型 ----->信息摘要
     */
    public static ASN1ObjectIdentifier digestedData_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.5");
    /**
     * PKCS#7: 1.2.840.113549.1.7.5
     */
    public static ASN1ObjectIdentifier digestedData_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.5").intern();

    /**
     * Encrypted-data内容类型 ----->加密数据
     */
    public static ASN1ObjectIdentifier encryptedData_GM = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.6");
    /**
     * PKCS#7: 1.2.840.113549.1.7.76
     */
    public static ASN1ObjectIdentifier encryptedData_RFC = new ASN1ObjectIdentifier("1.2.840.113549.1.7.6").intern();


    /**
     * Attributes 签名者签名属性的集合
     */
    public static  ASN1ObjectIdentifier authenticate_contentType = PKCSObjectIdentifiers.pkcs_9_at_contentType;
    public static  ASN1ObjectIdentifier authenticate_messageDigest = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
    public static  ASN1ObjectIdentifier authenticate_signingTime = PKCSObjectIdentifiers.pkcs_9_at_signingTime;


    public static ASN1ObjectIdentifier getDataObjectIdentifier(String algorithm) {
        return algorithm.contains(GM)? GMPKCSObjectIdentifiers.data_GM : GMPKCSObjectIdentifiers.data_RFC;
    }

    public static ASN1ObjectIdentifier getSignDataObjectIdentifier(String algorithm) {
        return algorithm.contains(GM) ? GMPKCSObjectIdentifiers.signedData_GM : GMPKCSObjectIdentifiers.signedData_RFC;
    }

    public static ASN1ObjectIdentifier getSignAlgorithmObjectIdentifier(String algorithm) {
        return algorithm.contains(GM) ? GMObjectIdentifiers.sm2sign : PKCSObjectIdentifiers.rsaEncryption;
    }
}
