package com.stamp.platform.bean.pkcs7;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;

import java.util.*;

/**
 * 数字签名类型为SignedData,生成SEQUENCE类型的SignedData，并填充到ContentInfo里的content里。
 * SignedData::= SEQUENCE {
 * version  Version,
 * digestAlgorithms DigestAlgorithmIdentifiers,
 * contentInfo  ContentInfo,
 * certificates [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 * crls[1] IMPLICIT CertificateRevocationLists OPTIONAL,
 * signerInfos SignerInfos
 * }
 *
 * @description: SignedDataExt
 * @date: 2022/9/23 14:51
 * @author: fanqie
 */
public class SignedDataExt extends SignedData {
    /**
     * 消息摘要算法标识符的集合，用来标识每个签名者使用的消息摘要算法
     * DigestAlgorithmIdentifier::= AlgorithmIdentifier
     * AlgorithmIdentifier::= SEQUENCE {
     * algorithm OBJECT IDENTIFIER,
     * parameters ANY DEFINED BY algorithm OPTIONAL
     * }
     */
    List<AlgorithmIdentifier> digestAlgorithmList;

    /**
     * certificates是签名使用的证书集合,每一个元素是X.509证书或PKCS＃6扩展证书，它是可选的
     */
    List<Certificate> certificateList;

    /**
     * crls是证书吊销列表（CRL）的集合，它也是可选的
     * 所谓证书吊销列表就是由CA发布的、在它所发放证书中已经被吊销的证书的列表名单。通过CRL对比验证，我们可以确定证书是否被吊销。
     * 在实际使用中，加入CRL验证是一件比较复杂的事情，一般不加
     */
    List<CertificateList> certificateCrlLists;

    /**
     * signerInfos是每个签名者信息的集合
     */
    List<SignerInfoExt> signerInfoList;


    /**
     * 签名者的证书集合<证书序列号,证书>
     */
    Map<ASN1Integer, Certificate> serialNumberAndCert;

    public SignedDataExt(ASN1Integer _version, ASN1Set _digestAlgorithms, ContentInfo _contentInfo, ASN1Set _certificates, ASN1Set _crls, ASN1Set _signerInfos) {
        super(_version, _digestAlgorithms, _contentInfo, _certificates, _crls, _signerInfos);
    }

    public SignedDataExt(ASN1Sequence seq) {
        super(seq);
        if (super.getDigestAlgorithms() != null && super.getDigestAlgorithms().size() > 0) {
            this.digestAlgorithmList = parsingASN1Set(super.getDigestAlgorithms(), 1);
        }

        if (super.getCertificates() != null && super.getCertificates().size() > 0) {
            this.certificateList = parsingASN1Set(super.getCertificates(), 2);
        }
        if (super.getCRLs() != null && super.getCRLs().size() > 0) {
            this.certificateCrlLists = parsingASN1Set(super.getCRLs(), 3);
        }

        if (super.getSignerInfos() != null && super.getSignerInfos().size() > 0) {
            this.signerInfoList = parsingASN1Set(super.getSignerInfos(), 4);
        }
    }

    public static SignedDataExt getInstance(
            Object o) {
        if (o instanceof SignedDataExt) {
            return (SignedDataExt) o;
        } else if (o != null) {
            return new SignedDataExt(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public List<AlgorithmIdentifier> getDigestAlgorithmList() {
        return digestAlgorithmList;
    }

    public List<Certificate> getCertificateList() {
        return certificateList;
    }

    public List<CertificateList> getCertificateCrlLists() {
        return certificateCrlLists;
    }

    public List<SignerInfoExt> getSignerInfoList() {
        return signerInfoList;
    }

    public Map<ASN1Integer, Certificate> getSerialNumberAndCert() {
        if (this.serialNumberAndCert != null && this.serialNumberAndCert.size() > 0) {
            return this.serialNumberAndCert;
        }
        this.serialNumberAndCert = new HashMap<>();
        if (certificateList != null && certificateList.size() > 0) {
            certificateList.forEach(item -> {
                this.serialNumberAndCert.put(item.getSerialNumber(), item);
            });

        }
        return this.serialNumberAndCert;
    }

    public static final ASN1Integer VERSION_1 = new ASN1Integer(1L);
    public static final ASN1Integer VERSION_3 = new ASN1Integer(3L);
    public static final ASN1Integer VERSION_4 = new ASN1Integer(4L);
    public static final ASN1Integer VERSION_5 = new ASN1Integer(5L);

    public static ASN1Integer calculateVersion(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Set paramASN1Set1, ASN1Set paramASN1Set2, ASN1Set paramASN1Set3) {
        int i = 0;
        int j = 0;
        int k = 0;
        int l = 0;
        Enumeration localEnumeration;
        Object localObject;
        if (paramASN1Set1 != null) {
            localEnumeration = paramASN1Set1.getObjects();
            while (localEnumeration.hasMoreElements()) {
                localObject = localEnumeration.nextElement();
                if (localObject instanceof ASN1TaggedObject) {
                    ASN1TaggedObject localASN1TaggedObject = ASN1TaggedObject.getInstance(localObject);
                    if (localASN1TaggedObject.getTagNo() == 1) {
                        k = 1;
                    } else if (localASN1TaggedObject.getTagNo() == 2) {
                        l = 1;
                    } else if (localASN1TaggedObject.getTagNo() == 3) {
                        i = 1;
                    }
                }
            }
        }
        if (i != 0) {
            return new ASN1Integer(5L);
        }
        if (paramASN1Set2 != null) {
            localEnumeration = paramASN1Set2.getObjects();
            while (localEnumeration.hasMoreElements()) {
                localObject = localEnumeration.nextElement();
                if (localObject instanceof ASN1TaggedObject) {
                    j = 1;
                }
            }
        }
        if (j != 0) {
            return VERSION_5;
        }
        if (l != 0) {
            return VERSION_4;
        }
        if (k != 0) {
            return VERSION_3;
        }
        if (checkForVersion3(paramASN1Set3)) {
            return VERSION_3;
        }
        if (!(CMSObjectIdentifiers.data.equals(paramASN1ObjectIdentifier))) {
            return VERSION_3;
        }
        return VERSION_1;
    }

    private static boolean checkForVersion3(ASN1Set paramASN1Set) {
        Enumeration localEnumeration = paramASN1Set.getObjects();
        while (localEnumeration.hasMoreElements()) {
            SignerInfo localSignerInfo = SignerInfo.getInstance(localEnumeration.nextElement());
            if (localSignerInfo.getVersion().getValue().intValue() == 3) {
                return true;
            }
        }
        return false;
    }

    private List parsingASN1Set(ASN1Set asn1Set, int clazz) {
        Iterator<ASN1Encodable> iterator = asn1Set.iterator();
        List list = new ArrayList<>();
        while (iterator.hasNext()) {
            ASN1Encodable next = iterator.next();
            if (clazz == 1) {
                AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(next);
                list.add(algorithmIdentifier);
            } else if (clazz == 2) {
                Certificate certificate = Certificate.getInstance(next);
                list.add(certificate);
            } else if (clazz == 3) {
                CertificateList certificateList = CertificateList.getInstance(next);
                list.add(certificateList);
            } else if (clazz == 4) {
                SignerInfoExt signerInfo = SignerInfoExt.getInstance(next);
                list.add(signerInfo);
            }


        }
        return list;
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        return super.toASN1Primitive();
    }


}
