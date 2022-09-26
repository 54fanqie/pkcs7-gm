package com.test.bean;


import com.stamp.platform.bean.sealcert.CertName;
import com.stamp.platform.bean.sealcert.Certificate;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 *  是签名证书的签发者标识及序列号
 * IssuerAndSerialNumber::= SEQUENCE {
 *          issuer Name,
 *          serialNumber CertificateSerialNumber
 * }
 * @description: IssuerAndSerialNumber
 * @date: 2022/8/24 17:58
 * @author: fanqie
 */
public class IssuerAndSerialNumber extends ASN1Object {

    /**
     * 颁发者
     * 国家、省份、地市、组织、机构、用户
     */
    private CertName issuer;


    /**
     * 证书序列号
     * <p>
     * CA分配给每个证书的一个正整数，一个CA签发的每张证书的序列号必须是唯一的。
     * CA必须保证序列号是非负整数。
     * 序列号可以是长整数，证书用户必须能够处理长达20个8位字节的序列号值。
     * CA必须确保不使用大于20个8位字节的序列号。
     */
    private ASN1Integer serialNumber;


    public static IssuerAndSerialNumber getInstance(Object var0) {
        if (var0 instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber)var0;
        } else {
            return var0 != null ? new IssuerAndSerialNumber(ASN1Sequence.getInstance(var0)) : null;
        }
    }

    public IssuerAndSerialNumber(ASN1Sequence var1) {
        Enumeration e = var1.getObjects();
        this.issuer = CertName.getInstance(e.nextElement());
        if (e.hasMoreElements()){
            this.serialNumber = (ASN1Integer)e.nextElement();
        }

    }

    public IssuerAndSerialNumber(Certificate var1) {
        this.issuer = var1.getTbsCertificate().getIssuer();
        this.serialNumber = var1.getTbsCertificate().getSerialNumber();
    }

    public IssuerAndSerialNumber(CertName var1, BigInteger var2) {
        this.issuer = var1;
        this.serialNumber = new ASN1Integer(var2);
    }

    public IssuerAndSerialNumber(X500Name var1, BigInteger var2) {
        RDN[] rdNs = var1.getRDNs();
        ASN1EncodableVector var3 = new ASN1EncodableVector(rdNs.length);
        for (RDN rdN : rdNs) {
            var3.add(rdN.toASN1Primitive());
        }
        this.issuer = CertName.getInstance(new DERSequence(var3));
        this.serialNumber = new ASN1Integer(var2);
    }



    public X500Name getName() {
        return X500Name.getInstance(this.issuer.toASN1Primitive());
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector(2);
        var1.add(this.issuer.toASN1Primitive());
        var1.add(this.serialNumber);
        return new DERSequence(var1);
    }
}
