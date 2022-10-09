package com.stamp.platform;

import com.stamp.platform.bean.GMPKCSObjectIdentifiers;
import com.stamp.platform.bean.bc.ELS_BcContentVerifierProviderBuilder;
import com.stamp.platform.bean.bc.ELS_SignerInformation;
import com.stamp.platform.bean.bc.ELS_SignerInformationVerifier;
import com.stamp.platform.bean.bc.algorithm.ELS_AlgorithmIdentifierFinderProvider;
import com.stamp.platform.bean.bc.outputStream.ELS_DigestCalculatorProvider;
import com.stamp.platform.bean.pkcs7.SWContentInfo;
import com.stamp.platform.bean.pkcs7.SignedDataExt;
import com.stamp.platform.bean.pkcs7.SignerInfoExt;
import com.stamp.platform.bean.sealcert.Time;
import com.stamp.platform.common.SignActionInterface;
import com.stamp.platform.util.DateUtil;
import com.stamp.platform.util.HexUtil;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

/**
 * 数字签名pkcs7
 *
 * @description: Pkcs7Factory4
 * @date: 2022/9/15 17:03
 * @author: fanqie
 */
public class Pkcs7Factory {
    private static final Logger logger = LoggerFactory.getLogger(Pkcs7Factory.class);

    /**
     * 解析数字签名数据PKCS7
     *
     * @param pkcs7Byte
     * @return SignedDataExt
     */
    public static SignedDataExt getELS_PKCS(byte[] pkcs7Byte) {
        try {
            if (pkcs7Byte == null || pkcs7Byte.length == 0) {
                logger.info("签名数据不能为空 ");
                new RuntimeException("签名数据不能为空");
            }
            Map hashes = new HashMap();
            SWContentInfo cmsSingedData = new SWContentInfo(hashes, pkcs7Byte);
            /**
             * 获取signedData中的证书集合
             *
             * certificates是PKCS#6扩展的证书和X.509证书格式。它表示集合足以包含从可识别的`根` 或`顶级ca` 到SignerInfo域中所有签名者的证书链，可能有多于必要的证书
             * 并且可能包含足够的证书链，但也有可能少于必要的证书，不如验证签名有一个替换方法来获得必要的证书，从先前证书集合中
             */
            return cmsSingedData.getSignedData();
        } catch (Exception e) {
            logger.error("解析 ASN.1格式下的PKCS# 7 错误" + e);
            throw new RuntimeException("签名数据不能为空");
        }
    }

    /**
     * 生成 pkcs7 数字签名
     * 国密算法 依据GM/T 0010-2012 (SM2密码算法加密签名消息语法规范)
     * 国际算法 RFC
     *
     * @param hash                    待签名内容 存在情况，为原文摘要值
     * @param digestAlgorithm         摘要算法标识
     * @param certificate             签名公钥所对应的证书
     * @param authenticatedAttributes 签名者签名属性的集合
     * @param signActionInterface     签名实现
     * @return byte[]
     */
    public static byte[] digitalSign(byte[] hash, AlgorithmIdentifier digestAlgorithm, byte[] certificate, ASN1Set authenticatedAttributes, SignActionInterface signActionInterface) {
        //根据证书确定签名算法
        X509CertificateHolder holder = null;
        try {
            holder = new X509CertificateHolder(certificate);
        } catch (IOException e) {
            logger.error("证书解析错误：" + e);
            throw new RuntimeException("证书解析错误" + e);
        }
        ASN1ObjectIdentifier objectIdentifier = holder.getSignatureAlgorithm().getAlgorithm();
        ELS_AlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider = ELS_AlgorithmIdentifierFinderProvider.INSTAN;
        String encryptionAlgName = algorithmIdentifierFinderProvider.getEncryptionAlgName(objectIdentifier);


        //digestEncryptionAlgorithm 摘要加密算法
        String algorithm = encryptionAlgName.equals(GMPKCSObjectIdentifiers.RSA) ? GMPKCSObjectIdentifiers.RSA : GMPKCSObjectIdentifiers.GM;
        AlgorithmIdentifier digestEncryptionAlgorithm = new AlgorithmIdentifier(GMPKCSObjectIdentifiers.getSignAlgorithmObjectIdentifier(algorithm), DERNull.INSTANCE);

        //SignData
        //DigestAlgorithmIdentifiers 消息摘要算法标识
        ASN1EncodableVector var1 = new ASN1EncodableVector(1);
        var1.add(digestAlgorithm);
        ASN1Set digestAlgorithmSet = new DLSet(var1);

        //ContentInfo  待签名内容(可选)
        ASN1OctetString content = null;
        if (hash != null && hash.length > 0) {
            content = new DEROctetString(hash);
        }
        ContentInfo paramContentInfo = new ContentInfo(GMPKCSObjectIdentifiers.getDataObjectIdentifier(algorithm), content);

        //ExtendedCertificatesAndCertificates  PKCS＃6扩展证书和X.509证书的集合
        ASN1EncodableVector var2 = new ASN1EncodableVector(1);
        var2.add(holder.toASN1Structure());
        ASN1Set certSet = new DLSet(var2);


        //SignInfo集合
        //issuerAndSerialNumber 通过颁发者的可辨别名和颁发序列号来指定签名者的证书
        X500Name issuer = holder.getIssuer();
        BigInteger serialNumber = holder.getSerialNumber();
        IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(issuer, serialNumber);


        //SignerInfo的数据结构
        SignerInfo signerInfo = null;
        try {
            byte[] signValue;
            //根据PKCS#7标准，如果没有authenticatedAttributes元素，
            // 这里的摘要指原文的摘要；否则就是authenticatedAttributes的摘要
            if (authenticatedAttributes == null) {
                if (hash == null || hash.length == 0) {
                    logger.error("没有authenticatedAttributes元素，需要传入原文");
                    throw new RuntimeException("没有authenticatedAttributes元素，需要传入原文");
                }
                signValue = signActionInterface.sign(hash);
            } else {
                byte[] attributesEncoded = authenticatedAttributes.getEncoded(ASN1Encoding.DER);
                signValue = signActionInterface.sign(attributesEncoded);
            }
            ASN1Integer version = new ASN1Integer(1L);
            signerInfo = new SignerInfoExt(version, issuerAndSerialNumber, digestAlgorithm, authenticatedAttributes, digestEncryptionAlgorithm, new DEROctetString(signValue), null);
        } catch (Exception e) {
            logger.error("SignerInfo的数据结构发生错误 ：" + e);
        }
        SignedDataExt signedData = new SignedDataExt(SignedDataExt.VERSION_1, digestAlgorithmSet, paramContentInfo, certSet, null, new DERSet(signerInfo));
        ContentInfo contentInfo = new ContentInfo(GMPKCSObjectIdentifiers.getSignDataObjectIdentifier(algorithm), signedData);
        try {
            return contentInfo.getEncoded();
        } catch (IOException e) {
            logger.error("pkcs7序列化数据错误：" + e);
            throw new RuntimeException("pkcs7序列化数据错误" + e);
        }
    }


    /**
     * 组装认证属性
     *
     * @param hash            原文摘要
     * @param digestAlgorithm 算法类型 SM2 或RSA
     * @return org.bouncycastle.asn1.ASN1Set
     */
    public static ASN1Set buildAuthenticatedAttributes(byte[] hash, AlgorithmIdentifier digestAlgorithm) {
        //authenticatedAttributes Attributes 签名者签名属性的集合
        //contentType 原文类型
        ELS_AlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider = ELS_AlgorithmIdentifierFinderProvider.INSTAN;
        String digestAlgName = algorithmIdentifierFinderProvider.getDigestAlgName(digestAlgorithm.getAlgorithm());
        Attribute attribute1 = new Attribute(GMPKCSObjectIdentifiers.authenticate_contentType, new DERSet(GMPKCSObjectIdentifiers.getDataObjectIdentifier(digestAlgName)));
        //messageDigest 原文摘要
        Attribute attribute2 = new Attribute(GMPKCSObjectIdentifiers.authenticate_messageDigest, new DERSet(new DEROctetString(hash)));
        //signingTime 签名时间
        Time time = new Time(new Date(), Locale.CHINA);
        Attribute attribute3 = new Attribute(GMPKCSObjectIdentifiers.authenticate_signingTime, new DERSet(time));
        ASN1EncodableVector var3 = new ASN1EncodableVector(3);
        var3.add(attribute1);
        var3.add(attribute2);
        var3.add(attribute3);
        return new DLSet(var3);
    }


    /**
     * 生成 pkcs7 数字签名
     * 国密算法 依据GM/T 0010-2012 (SM2密码算法加密签名消息语法规范)
     * 国际算法 RFC
     *
     * @param hash      原文摘要
     * @param pkcs7Byte 数字签名结构
     * @return void
     */
    public static boolean digitalSignVerify(byte[] hash, byte[] pkcs7Byte) {
        logger.info("==========================开始验签===========================");
        try {
            if (pkcs7Byte == null || pkcs7Byte.length == 0) {
                logger.info("签名数据不能为空 ");
                new RuntimeException("签名数据不能为空");
            }
            Map hashes = new HashMap();
            hashes.put(GMObjectIdentifiers.sm3, hash);
            SWContentInfo cmsSingedData = new SWContentInfo(hashes, pkcs7Byte);
            /**
             * 获取signedData中的证书集合
             *
             * certificates是PKCS#6扩展的证书和X.509证书格式。它表示集合足以包含从可识别的`根` 或`顶级ca` 到SignerInfo域中所有签名者的证书链，可能有多于必要的证书
             * 并且可能包含足够的证书链，但也有可能少于必要的证书，不如验证签名有一个替换方法来获得必要的证书，从先前证书集合中
             */
            SignedDataExt signedData = cmsSingedData.getSignedData();
            Map<ASN1Integer, Certificate> certHashMap = signedData.getSerialNumberAndCert();

            /**
             *
             *  获得SignerInformation 摘要算法与签名者集合
             */
            List<ELS_SignerInformation> signers = cmsSingedData.getSignerInfos();
            Iterator it = signers.iterator();
            int count = 0;
            while (it.hasNext()) {
                ELS_SignerInformation signer = (ELS_SignerInformation) it.next();
                logger.info("密码杂凑算法标识 " + signer.getDigestAlgOID());

                // 签名值
                byte[] signed = signer.getSignature();
                logger.info("椭曲线数字签名算法标识符 " + signer.getEncryptionAlgOID());
                logger.info("签名值length=" + HexUtil.byteToHex(signed));
                //签名证书序列号
                ASN1Integer serialNumber = signer.getIssuerAndSerialNumber().getCertificateSerialNumber();
                Certificate certificate = certHashMap.get(serialNumber);
                X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());

                //算法查找类
                ELS_AlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider = ELS_AlgorithmIdentifierFinderProvider.INSTAN;
                //摘要计算类
                DigestCalculatorProvider bcDigestProvider = ELS_DigestCalculatorProvider.INSTANCE;
                ContentVerifierProvider contentVerifierProvider = new ELS_BcContentVerifierProviderBuilder().build(holder);
                //构建验证类
                ELS_SignerInformationVerifier bc = new ELS_SignerInformationVerifier(algorithmIdentifierFinderProvider,
                        contentVerifierProvider, bcDigestProvider
                );

                // 验证数字签名
                boolean verifyRet = signer.verify(bc);
                if (verifyRet) {
                    logger.info("成功");
                    count++;
                } else {
                    logger.error("失败");
                }
            }
            return count == signers.size();
        } catch (Exception e) {
            logger.error("digitalSignVerify ASN.1格式下的PKCS# 7 错误" + e);
            return false;
        }
    }
}
