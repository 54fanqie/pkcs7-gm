package com.stamp.platform.bean.pkcs7;

import com.stamp.platform.bean.bc.SwSignerInformation;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @description: SWContentInfo
 * @date: 2022/9/1 15:57
 * @author: fanqie
 */
public class SWContentInfo {
    private static final Logger logger = LoggerFactory.getLogger(SWContentInfo.class);
    private SignedDataExt signedData;
    private ContentInfo contentInfo;
    /**
     *  SignedData内的结构信息中的待签名信息
     */
    private ProcessableContent signedContent;
    /**
     * 对认证属性做的摘要
     * 根据PKCS#7标准，如果没有authenticatedAttributes元素，这里的摘要指原文的摘要hashes；
     * 否则就是authenticatedAttributes的摘要
     */

    private Map hashes;

    public SWContentInfo(byte[] contentInfo) {
        getInstants(ContentInfo.getInstance(contentInfo));
    }

    public SWContentInfo(
            Map hashes,
            byte[] sigData) {
        this.hashes = hashes;
        getInstants(ContentInfo.getInstance(sigData));
    }
    private void getInstants(ContentInfo sigData) {
        this.contentInfo = sigData;
        this.signedData = SignedDataExt.getInstance(contentInfo.getContent());

        ASN1Encodable content = signedData.getContentInfo().getContent();
        //SignData 存在 contentInfo 待签名内容，没有content的情况
        if (content != null) {
            if (content instanceof ASN1OctetString) {
                try {
                    this.signedContent = new ProcessableContent(signedData.getContentInfo().getContentType(),
                            ((ASN1OctetString) content).toASN1Primitive().getEncoded());
                    logger.info("signData中的contentInfo是被签名的原文内容存在，获取原文内容为ASN1OctetString");
                } catch (IOException e) {
                    throw new RuntimeException("contentInfo里的content元素解析错误");
                }
            } else {
                logger.info("signData中的contentInfo是被签名的原文内容存在，获取原文内容结构未知");
                this.signedContent = new ProcessableContent(signedData.getContentInfo().getContentType(), content);
            }
        } else {
            this.signedContent = null;
            if (hashes == null){
                //原文为空，并且未外送原文摘要
                throw new RuntimeException("SignData中的contentInfo里的content元素不存在时，即签名中不包括原文内容。这种签名与正文分离的模式，要求验证签名时原文需另外提供");
            }
        }
    }

    public SignedDataExt getSignedData() {
        return signedData;
    }

    public ContentInfo getContentInfo() {
        return contentInfo;
    }

    public List<SwSignerInformation> getSignerInfos() {
        ASN1Set s = signedData.getSignerInfos();
        List<SwSignerInformation> signerInfos = new ArrayList();
        for (int i = 0; i != s.size(); i++) {
            SignerInfoExt info = SignerInfoExt.getInstance(s.getObjectAt(i));
            ASN1ObjectIdentifier contentType = signedData.getContentInfo().getContentType();
            if (hashes == null) {
                signerInfos.add(new SwSignerInformation(info, contentType, signedContent, null));
            } else {
                Object obj = hashes.keySet().iterator().next();
                byte[] hash = (obj instanceof String) ? (byte[]) hashes.get(info.getDigestAlgorithm().getAlgorithm().getId()) : (byte[]) hashes.get(info.getDigestAlgorithm().getAlgorithm());
                signerInfos.add(new SwSignerInformation(info, contentType, null, hash));
            }
        }
        return signerInfos;
    }

}
