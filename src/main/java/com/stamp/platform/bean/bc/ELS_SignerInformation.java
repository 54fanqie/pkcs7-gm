package com.stamp.platform.bean.bc;

import com.stamp.platform.bean.bc.algorithm.ELS_AlgorithmIdentifierFinderProvider;
import com.stamp.platform.bean.pkcs7.ProcessableContent;
import com.stamp.platform.bean.pkcs7.SignerInfoExt;
import com.stamp.platform.util.HexUtil;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;


/**
 * @description: SignerInformation
 * @date: 2022/8/31 14:13
 * @author: fanqie
 */
public class ELS_SignerInformation {
    private static final Logger logger = LoggerFactory.getLogger(ELS_SignerInformation.class);

    private IssuerAndSerialNumber issuerAndSerialNumber;
    /**
     *  SignedData内的结构信息中的待签名信息
     */
    private ProcessableContent content;
    /**
     *  SignerInfo的数据结构
     */
    protected SignerInfoExt info;
    protected AlgorithmIdentifier digestAlgorithm;
    protected AlgorithmIdentifier encryptionAlgorithm;
    /**
     *  signInfo中签名值
     */
    private byte[] signature;
    private ASN1ObjectIdentifier contentType;
    private boolean isCounterSignature;

    /**
     *  signInfo中认证属性：原文属性类型、原文摘要、签名时间（可选）
     */
    private AttributeTable signedAttributeValues;
    protected ASN1Set signedAttributeSet;
    /**
     *  signInfo中不被签名的属性的集合（可选）
     */
    private AttributeTable unsignedAttributeValues;
    protected ASN1Set unsignedAttributeSet;

    /**
     * 外送的原文摘要
     */
    private byte[] resultDigest;



    public ELS_SignerInformation(
            SignerInfoExt info,
            ASN1ObjectIdentifier contentType,
            ProcessableContent content,
            byte[] resultDigest) {
        this.info = info;
        this.contentType = contentType;
        this.isCounterSignature = contentType == null;
        this.issuerAndSerialNumber = info.getIssuerAndSerialNumber();
        this.digestAlgorithm = info.getDigestAlgorithm();
        this.signedAttributeSet = info.getAuthenticatedAttributes();
        this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
        this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
        this.signature = info.getEncryptedDigest().getOctets();
        this.content = content;
        //此参数为外送原文摘要
        this.resultDigest = resultDigest;
    }


    /**
     * Verify that the given verifier can successfully verify the signature on
     * this SignerInformation object.
     *
     * @param verifier a suitably configured SignerInformationVerifier.
     * @return true if the signer information is verified, false otherwise.
     * @throws org.bouncycastle.cms.CMSVerifierCertificateNotValidException if the provider has an associated certificate and the certificate is not valid at the time given as the SignerInfo's signing time.
     * @throws org.bouncycastle.cms.CMSException                            if the verifier is unable to create a ContentVerifiers or DigestCalculators.
     */
    public boolean verify(ELS_SignerInformationVerifier verifier)
            throws CMSException {
        Time signingTime = getSigningTime();   // has to be validated if present.

        if (verifier.hasAssociatedCertificate()) {
            if (signingTime != null) {
                X509CertificateHolder dcv = verifier.getAssociatedCertificate();

                if (!dcv.isValidOn(signingTime.getDate())) {
                    throw new CMSVerifierCertificateNotValidException("verifier not valid at signingTime");
                }
            }
        }

        return doVerify(verifier);
    }

    private boolean doVerify(
            ELS_SignerInformationVerifier verifier)
            throws CMSException {

        String encName = ELS_AlgorithmIdentifierFinderProvider.INSTAN.getEncryptionAlgName(encryptionAlgorithm.getAlgorithm());
        ContentVerifier contentVerifier;

        try {
            //根据签名算法标识和摘要算法标识，生成ContentVerifier签名验证类
            contentVerifier = verifier.getContentVerifier(encryptionAlgorithm, info.getDigestAlgorithm());
        } catch (OperatorCreationException e) {
            throw new CMSException("can't create content verifier: " + e.getMessage(), e);
        }

        try {
            //返回用于验证的签名数据流
            OutputStream sigOut = contentVerifier.getOutputStream();
            //如果外送原文摘要为空,则对认证属性计算摘要
            if (resultDigest == null) {
                //根据摘要算法，获取摘要计算器
                DigestCalculator calc = verifier.getDigestCalculator(this.getDigestAlgorithmID());
                /**
                 * 根据PKCS#7标准
                 * 如果没有authenticatedAttributes元素，这里的摘要指原文的摘要；
                 * 否则就是authenticatedAttributes的摘要
                 */
                // 返回用于摘要计算的数据流
                OutputStream digOut = calc.getOutputStream();
                // 待签名原文不为空
                if (content != null) {
                    //第一种：认证属性为空
                    if (signedAttributeSet == null) {
                        //验证预期的签名值是从传入的摘要中派生出来的
                        if (contentVerifier instanceof RawContentVerifier) {
                            //场景：摘要计算流 获取到原文
                            content.write(digOut);
                        } else {
                            //场景：认证属性项为空 ，待签名原文存在
                            OutputStream cOut = new TeeOutputStream(digOut, sigOut);
                            content.write(cOut);
                            cOut.close();
                        }
                    } else {
                        //第二种：认证属性不为空
                        //场景：待签名原文进行摘要，并从认证属性中获取签名值
                        content.write(digOut);
                        sigOut.write(this.getEncodedSignedAttributes());
                    }
                } else if (signedAttributeSet != null) {
                    //对认证属性进行摘要 SM2Signer 内部实现了SM3Digest摘要算法
                    byte[] encodedSignedAttributes = this.getEncodedSignedAttributes();
                    sigOut.write(encodedSignedAttributes);
                    //主要用于比对摘要
                    digOut.write(encodedSignedAttributes);
                } else {
                    // TODO Get rid of this exception and just treat content==null as empty not missing?
                    throw new CMSException("缺少原文内容，缺少认证属性");
                }
                digOut.close();
                //获取摘要： 可能是原文原文的摘要  可能是认证属性的摘要
                resultDigest = calc.getDigest();
                logger.error("走到这一步就会发生错误，下面会判断原文摘要与认证属性内的原文摘要是否一致");
            } else {
                //如果外送原文摘要不为空
                /**
                 * 根据PKCS#7标准
                 * 如果没有authenticatedAttributes元素，这里的摘要指原文的摘要；
                 * 否则就是authenticatedAttributes的摘要
                 */
                if (signedAttributeSet == null) {
                    if (content != null) {
                        content.write(sigOut);
                    }
                } else {
//                    SignerInformationStore
                    //对认证属性进行摘要 SM2Signer 内部实现了SM3Digest摘要算法
                    byte[] encodedSignedAttributes = this.getEncodedSignedAttributes();
                    sigOut.write(encodedSignedAttributes);
                }
            }
            sigOut.close();
        } catch (IOException e) {
            throw new CMSException("can't process mime object to create signature.", e);
        } catch (OperatorCreationException e) {
            throw new CMSException("can't create digest calculator: " + e.getMessage(), e);
        }

        // RFC 3852 11.1 Check the content-type attribute is correct
        {
            ASN1Primitive validContentType = getSingleValuedSignedAttribute(
                    CMSAttributes.contentType, "content-type");
            if (validContentType == null) {
                if (!isCounterSignature && signedAttributeSet != null) {
                    throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
                }
            } else {
                if (isCounterSignature) {
                    throw new CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
                }

                if (!(validContentType instanceof ASN1ObjectIdentifier)) {
                    throw new CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
                }

                ASN1ObjectIdentifier signedContentType = (ASN1ObjectIdentifier) validContentType;

                if (!signedContentType.equals(contentType)) {
                    throw new CMSException("content-type attribute value does not match eContentType");
                }
            }
        }

        AttributeTable signedAttrTable = this.getSignedAttributes();

        // RFC 6211 Validate Algorithm Identifier protection attribute if present
        {
            AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
            if (unsignedAttrTable != null && unsignedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect).size() > 0) {
                throw new CMSException("A cmsAlgorithmProtect attribute MUST be a signed attribute");
            }
            if (signedAttrTable != null) {
                ASN1EncodableVector protectionAttributes = signedAttrTable.getAll(CMSAttributes.cmsAlgorithmProtect);
                if (protectionAttributes.size() > 1) {
                    throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
                }

                if (protectionAttributes.size() > 0) {
                    Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
                    if (attr.getAttrValues().size() != 1) {
                        throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
                    }

                    CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);

                    if (!isEquivalent(algorithmProtection.getDigestAlgorithm(), info.getDigestAlgorithm())) {
                        throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
                    }

                    if (!isEquivalent(algorithmProtection.getSignatureAlgorithm(), info.getDigestEncryptionAlgorithm())) {
                        throw new CMSException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm");
                    }
                }
            }
        }

        // RFC 3852 11.2 Check the message-digest attribute is correct
        //签名认证属性
        {
            //messageDigest 属性标识为“原文摘要”："1.2.840.113549.1.9.4"
            ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(
                    CMSAttributes.messageDigest, "message-digest");
            if (validMessageDigest == null) {
                if (signedAttributeSet != null) {
                    throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
                }
            } else {
                if (!(validMessageDigest instanceof ASN1OctetString)) {
                    throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
                }
                byte[] signedMessageDigest = ((ASN1OctetString) validMessageDigest).getOctets();
                logger.info("认证属性中的原文摘要数据 ： " + HexUtil.byteToHex(signedMessageDigest));
                if (!Arrays.constantTimeAreEqual(resultDigest, signedMessageDigest)) {
                    throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
                }
            }
        }

        // RFC 3852 11.4 Validate countersignature attribute(s)
        {
            if (signedAttrTable != null
                    && signedAttrTable.getAll(CMSAttributes.counterSignature).size() > 0) {
                throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
            }

            AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
            if (unsignedAttrTable != null) {
                ASN1EncodableVector csAttrs = unsignedAttrTable.getAll(CMSAttributes.counterSignature);
                for (int i = 0; i < csAttrs.size(); ++i) {
                    Attribute csAttr = Attribute.getInstance(csAttrs.get(i));
                    if (csAttr.getAttrValues().size() < 1) {
                        throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
                    }

                    // Note: We don't recursively validate the countersignature value
                }
            }
        }

        try {
            if (signedAttributeSet == null && resultDigest != null) {
                if (contentVerifier instanceof RawContentVerifier) {
                    RawContentVerifier rawVerifier = (RawContentVerifier) contentVerifier;

                    if (encName.equals("RSA")) {
                        DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.getAlgorithm(), DERNull.INSTANCE), resultDigest);

                        return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), this.getSignature());
                    }

                    return rawVerifier.verify(resultDigest, this.getSignature());
                }
            }

            return contentVerifier.verify(this.getSignature());
        } catch (IOException e) {
            throw new CMSException("can't process mime object to create signature.", e);
        }
    }



    public boolean isCounterSignature() {
        return isCounterSignature;
    }

    public ASN1ObjectIdentifier getContentType() {
        return this.contentType;
    }

    private byte[] encodeObj(
            ASN1Encodable obj)
            throws IOException {
        if (obj != null) {
            return obj.toASN1Primitive().getEncoded();
        }

        return null;
    }

    /**
     * return the version number for this objects underlying SignerInfo structure.
     */
    public int getVersion() {
        return info.getVersion().intValueExact();
    }

    public AlgorithmIdentifier getDigestAlgorithmID() {
        return digestAlgorithm;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getDigestAlgOID() {
        return digestAlgorithm.getAlgorithm().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getDigestAlgParams() {
        try {
            return encodeObj(digestAlgorithm.getParameters());
        } catch (Exception e) {
            throw new RuntimeException("exception getting digest parameters " + e);
        }
    }

    /**
     * return the content digest that was calculated during verification.
     */
    public byte[] getContentDigest() {
        if (resultDigest == null) {
            throw new IllegalStateException("method can only be called after verify.");
        }

        return Arrays.clone(resultDigest);
    }

    /**
     * return the object identifier for the signature.
     */
    public String getEncryptionAlgOID() {
        return encryptionAlgorithm.getAlgorithm().getId();
    }

    /**
     * return the signature/encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams() {
        try {
            return encodeObj(encryptionAlgorithm.getParameters());
        } catch (Exception e) {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return issuerAndSerialNumber;
    }

    /**
     * return a table of the signed attributes - indexed by
     * the OID of the attribute.
     */
    public AttributeTable getSignedAttributes() {
        if (signedAttributeSet != null && signedAttributeValues == null) {
            signedAttributeValues = new AttributeTable(signedAttributeSet);
        }
        return signedAttributeValues;
    }

    /**
     * return a table of the unsigned attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnsignedAttributes() {
        if (unsignedAttributeSet != null && unsignedAttributeValues == null) {
            unsignedAttributeValues = new AttributeTable(unsignedAttributeSet);
        }
        return unsignedAttributeValues;
    }

    /**
     * return the encoded signature
     */
    public byte[] getSignature() {
        return Arrays.clone(signature);
    }


    /**
     * return the DER encoding of the signed attributes.
     *
     * @throws IOException if an encoding error occurs.
     */
    public byte[] getEncodedSignedAttributes()
            throws IOException {
        if (signedAttributeSet != null) {
            return signedAttributeSet.getEncoded(ASN1Encoding.DER);
        }

        return null;
    }


    /**
     * Return the underlying ASN.1 object defining this SignerInformation object.
     *
     * @return a SignerInfo.
     */
    public SignerInfoExt toASN1Structure() {
        return info;
    }

    private ASN1Primitive getSingleValuedSignedAttribute(
            ASN1ObjectIdentifier attrOID, String printableName)
            throws CMSException {
        AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
        if (unsignedAttrTable != null
                && unsignedAttrTable.getAll(attrOID).size() > 0) {
            throw new CMSException("The " + printableName
                    + " attribute MUST NOT be an unsigned attribute");
        }

        AttributeTable signedAttrTable = this.getSignedAttributes();
        if (signedAttrTable == null) {
            return null;
        }

        ASN1EncodableVector v = signedAttrTable.getAll(attrOID);
        switch (v.size()) {
            case 0:
                return null;
            case 1: {
                Attribute t;
                ASN1Encodable encodable = v.get(0);
                if (encodable instanceof Attribute) {
                    t = (Attribute) v.get(0);
                } else {
                    t = Attribute.getInstance(encodable.toASN1Primitive());
                }

                ASN1Set attrValues = t.getAttrValues();
                if (attrValues.size() != 1) {
                    throw new CMSException("A " + printableName
                            + " attribute MUST have a single attribute value");
                }

                return attrValues.getObjectAt(0).toASN1Primitive();
            }
            default:
                throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the "
                        + printableName + " attribute");
        }
    }

    private Time getSigningTime() throws CMSException {
        ASN1Primitive validSigningTime = getSingleValuedSignedAttribute(
                CMSAttributes.signingTime, "signing-time");

        if (validSigningTime == null) {
            return null;
        }

        try {
            return Time.getInstance(validSigningTime);
        } catch (IllegalArgumentException e) {
            throw new CMSException("signing-time attribute value not a valid 'Time' structure");
        }
    }


    static boolean isEquivalent(AlgorithmIdentifier algId1, AlgorithmIdentifier algId2) {
        if (algId1 == null || algId2 == null) {
            return false;
        }

        if (!algId1.getAlgorithm().equals(algId2.getAlgorithm())) {
            return false;
        }

        ASN1Encodable params1 = algId1.getParameters();
        ASN1Encodable params2 = algId2.getParameters();
        if (params1 != null) {
            return params1.equals(params2) || (params1.equals(DERNull.INSTANCE) && params2 == null);
        }

        return params2 == null || params2.equals(DERNull.INSTANCE);
    }
}
