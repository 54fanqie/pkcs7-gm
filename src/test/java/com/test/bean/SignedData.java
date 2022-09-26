package com.test.bean;


import com.stamp.platform.bean.crl.CertificateList;
import com.stamp.platform.bean.sealcert.Certificate;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

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
 * @description: SignedData
 * @date: 2022/8/24 18:04
 * @author: fanqie
 */
public class SignedData extends ASN1Object {
    private static final ASN1Integer VERSION_1 = new ASN1Integer(1L);
    private static final ASN1Integer VERSION_3 = new ASN1Integer(3L);
    private static final ASN1Integer VERSION_4 = new ASN1Integer(4L);
    private static final ASN1Integer VERSION_5 = new ASN1Integer(5L);
    /**
     * 整数类型，指PKCS#7语法的版本，目前取值为1。
     */
    ASN1Integer version;

    /**
     * 消息摘要算法标识符的集合，用来标识每个签名者使用的消息摘要算法
     * DigestAlgorithmIdentifier::= AlgorithmIdentifier
     * AlgorithmIdentifier::= SEQUENCE {
     * algorithm OBJECT IDENTIFIER,
     * parameters ANY DEFINED BY algorithm OPTIONAL
     * }
     */
    ASN1Set digestAlgorithms;

    List<AlgorithmIdentifier> digestAlgorithmList;


    /**
     * contentInfo是被签名的原文内容,结构为通用的ContentInfo类型.
     * 如果contentInfo里的content元素不存在时，即签名中不包括原文内容。这种签名与正文分离的模式，要求验证签名时原文需另外提供，这也是实际应用中常用的方式
     */
    ContentInfo contentInfo;


    /**
     * certificates是签名使用的证书集合,每一个元素是X.509证书或PKCS＃6扩展证书，它是可选的
     */
    ASN1Set certificates;

    List<Certificate> certificateList;


    /**
     * crls是证书吊销列表（CRL）的集合，它也是可选的
     * 所谓证书吊销列表就是由CA发布的、在它所发放证书中已经被吊销的证书的列表名单。通过CRL对比验证，我们可以确定证书是否被吊销。
     * 在实际使用中，加入CRL验证是一件比较复杂的事情，一般不加
     */
    ASN1Set crls;
    List<CertificateList> certificateCrlLists;

    /**
     * signerInfos是每个签名者信息的集合
     */
    ASN1Set signerInfos;
    List<SignerInfo> signerInfoList;

    private boolean certsBer;
    private boolean crlsBer;


    public SignedData(ASN1Set digestAlgorithms, ContentInfo paramContentInfo, ASN1Set certificates, ASN1Set crls, ASN1Set signerInfos) {
        this.version = calculateVersion(paramContentInfo.getContentType(), certificates, crls, signerInfos);
        this.digestAlgorithms = digestAlgorithms;
        this.contentInfo = paramContentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
        this.crlsBer = crls instanceof BERSet;
        this.certsBer = certificates instanceof BERSet;
    }

    private SignedData(ASN1Sequence paramASN1Sequence) {
        Enumeration localEnumeration = paramASN1Sequence.getObjects();
        this.version = ASN1Integer.getInstance(localEnumeration.nextElement());
        this.digestAlgorithms = ((ASN1Set) localEnumeration.nextElement());
        if (this.digestAlgorithms != null && this.digestAlgorithms.size() > 0) {
            this.digestAlgorithmList = parsingASN1Set(this.digestAlgorithms, 1);
        }
        this.contentInfo = ContentInfo.getInstance(localEnumeration.nextElement());
        while (localEnumeration.hasMoreElements()) {
            ASN1Primitive localASN1Primitive = (ASN1Primitive) localEnumeration.nextElement();
            if (localASN1Primitive instanceof ASN1TaggedObject) {
                ASN1TaggedObject localASN1TaggedObject = (ASN1TaggedObject) localASN1Primitive;
                switch (localASN1TaggedObject.getTagNo()) {
                    case 0:
                        this.certsBer = localASN1TaggedObject instanceof BERTaggedObject;
                        this.certificates = ASN1Set.getInstance(localASN1TaggedObject, false);
                        if (this.certificates != null && this.certificates.size() > 0) {
                            this.certificateList = parsingASN1Set(this.certificates, 2);
                        }
                        break;
                    case 1:
                        this.crlsBer = localASN1TaggedObject instanceof BERTaggedObject;
                        this.crls = ASN1Set.getInstance(localASN1TaggedObject, false);
                        if (this.crls != null && this.crls.size() > 0) {
                            this.certificateCrlLists = parsingASN1Set(this.crls, 3);
                        }
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + localASN1TaggedObject.getTagNo());
                }
            } else {
                this.signerInfos = ((ASN1Set) localASN1Primitive);
                if (this.signerInfos != null && this.signerInfos.size() > 0) {
                    this.signerInfoList = parsingASN1Set(this.signerInfos, 4);
                }
            }
        }
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
                SignerInfo signerInfo = SignerInfo.getInstance(next);
                list.add(signerInfo);
            }


        }
        return list;
    }

    public static SignedData getInstance(Object var0) {
        if (var0 instanceof SignedData) {
            return (SignedData)var0;
        } else {
            return var0 != null ? new SignedData(ASN1Sequence.getInstance(var0)) : null;
        }
    }

    private ASN1Integer calculateVersion(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Set paramASN1Set1, ASN1Set paramASN1Set2, ASN1Set paramASN1Set3) {
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

    private boolean checkForVersion3(ASN1Set paramASN1Set) {
        Enumeration localEnumeration = paramASN1Set.getObjects();
        while (localEnumeration.hasMoreElements()) {
            SignerInfo localSignerInfo = SignerInfo.getInstance(localEnumeration.nextElement());
            if (localSignerInfo.getVersion().getValue().intValue() == 3) {
                return true;
            }
        }
        return false;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public ASN1Set getDigestAlgorithms() {
        return this.digestAlgorithms;
    }

    public ContentInfo getEncapContentInfo() {
        return this.contentInfo;
    }

    public ASN1Set getCertificates() {
        return this.certificates;
    }

    public ASN1Set getCRLs() {
        return this.crls;
    }

    public ASN1Set getSignerInfos() {
        return this.signerInfos;
    }

    public List<Certificate> getCertificateList() {
        return certificateList;
    }

    public List<SignerInfo> getSignerInfoList() {
        return signerInfoList;
    }

    public List<CertificateList> getCertificateCrlLists() {
        return certificateCrlLists;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector localASN1EncodableVector = new ASN1EncodableVector();
        localASN1EncodableVector.add(this.version);
        localASN1EncodableVector.add(this.digestAlgorithms);
        localASN1EncodableVector.add(this.contentInfo);
        if (this.certificates != null) {
            if (this.certsBer) {
                localASN1EncodableVector.add(new BERTaggedObject(false, 0, this.certificates));
            } else {
                localASN1EncodableVector.add(new DERTaggedObject(false, 0, this.certificates));
            }
        }
        if (this.crls != null) {
            if (this.crlsBer) {
                localASN1EncodableVector.add(new BERTaggedObject(false, 1, this.crls));
            } else {
                localASN1EncodableVector.add(new DERTaggedObject(false, 1, this.crls));
            }
        }
        localASN1EncodableVector.add(this.signerInfos);
        return new BERSequence(localASN1EncodableVector);
    }






}
