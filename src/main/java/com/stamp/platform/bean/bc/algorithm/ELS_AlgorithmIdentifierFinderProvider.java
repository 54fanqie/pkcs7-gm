package com.stamp.platform.bean.bc.algorithm;

import com.stamp.platform.bean.bc.constants.IdentifiersConstants;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Strings;

import static com.stamp.platform.bean.bc.constants.IdentifiersConstants.digestOIDAndName;
import static com.stamp.platform.bean.bc.constants.IdentifiersConstants.encryptionAndName;

/**
 * @description: SWDigestAlgorithmIdentifierFinder
 * @date: 2022/8/31 16:22
 * @author: fanqie
 */
public class ELS_AlgorithmIdentifierFinderProvider {
    public static ELS_AlgorithmIdentifierFinderProvider INSTAN = new ELS_AlgorithmIdentifierFinderProvider();
    /**
     * 签名算法标识符
     * rsaEncryption	                RSA算法标识	        1.2.840.113549.1.1.1
     * sha1withRSAEncryption	        SHA1的RSA签名	    1.2.840.113549.1.1.5
     * ECC	                            ECC算法标识	        1.2.840.10045.2.1
     * SM2	                            SM2算法标识	        1.2.156.10197.1.301
     * SM3WithSM2	                    SM3的SM2签名	        1.2.156.10197.1.501
     * sha1withSM2	                    SHA1的SM2签名	    1.2.156.10197.1.502
     * sha256withSM2	                SHA256的SM2签名	    1.2.156.10197.1.503
     * sm3withRSAEncryption	            SM3的RSA签名	        1.2.156.10197.1.504
     * @date: 2022/8/30 19:23
     */


    /**
     * 根据摘要算法oid 返回摘要算法名称
     * Return the digest algorithm using one of the standard JCA string
     * representations rather than the algorithm identifier (if possible).
     */
    public String getDigestAlgName(
            ASN1ObjectIdentifier digestAlgOID)
    {
        String algName = (String)digestOIDAndName.get(digestAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return digestAlgOID.getId();
    }

    /**
     * 根据签名算法oid  返回签名算法名称
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    public String getEncryptionAlgName(
            ASN1ObjectIdentifier encryptionAlgOID)
    {
        String algName = (String)encryptionAndName.get(encryptionAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return encryptionAlgOID.getId();
    }
    /**
     * 设置摘要算法与签名算法的映射
     * 根据摘要算法标识  + 签名算法标识  返回混合算法签名算法名称 如 SM3WithSM2
     * @param digestAlg       摘要算法标识
     * @param encryptionAlg   签名算法标识
     * @return java.lang.String   SM3WithSM2
     */
    public String getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg)
    {
        ASN1ObjectIdentifier encryptionAlgAlgorithm = encryptionAlg.getAlgorithm();
        if (EdECObjectIdentifiers.id_Ed25519.equals(encryptionAlgAlgorithm))
        {
            return "Ed25519";
        }
        if (EdECObjectIdentifiers.id_Ed448.equals(encryptionAlgAlgorithm))
        {
            return "Ed448";
        }

        String digestName = getDigestAlgName(digestAlg.getAlgorithm());
        String id = encryptionAlgAlgorithm.getId();
        if (!digestName.equals(id))
        {
            return digestName + "with" + getEncryptionAlgName(encryptionAlgAlgorithm);
        }

        return getDigestAlgName(digestAlg.getAlgorithm()) + "with" + getEncryptionAlgName(encryptionAlgAlgorithm);
    }

    /**
     * 查找到与签名算法匹配的 摘要算法标识符
     *
     * @param sigAlgId 传入的签名算法标识符
     * @return 对应摘要的算法标识符
     */
    public AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId) {
        ASN1ObjectIdentifier sigAlgOid = sigAlgId.getAlgorithm();

        if (sigAlgOid.equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256_len, new ASN1Integer(512));
        }

        ASN1ObjectIdentifier digAlgOid;
        if (sigAlgOid.equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
        {
            digAlgOid = RSASSAPSSparams.getInstance(sigAlgId.getParameters()).getHashAlgorithm().getAlgorithm();
        }
        else if (sigAlgOid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            digAlgOid = NISTObjectIdentifiers.id_sha512;
        }
        else
        {
            digAlgOid = (ASN1ObjectIdentifier) IdentifiersConstants.aToDigestOids.get(sigAlgId.getAlgorithm());
        }

        return find(digAlgOid);
    }

    /**
     * 查找匹配的算法标识符
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param digAlgOid 传入的摘要名称
     * @return 摘要签名的算法标识符
     */
    public AlgorithmIdentifier find(ASN1ObjectIdentifier digAlgOid) {
        if (digAlgOid == null)
        {
            throw new NullPointerException("digest OID is null");
        }

        AlgorithmIdentifier digAlgId = (AlgorithmIdentifier)IdentifiersConstants.digestOidToAlgIds.get(digAlgOid);
        if (digAlgId == null)
        {
            return new AlgorithmIdentifier(digAlgOid);
        }
        else
        {
            return digAlgId;
        }
    }

    /**
     * 根据算法名称  返回算法标识
     * Find the signature algorithm identifier that matches with
     * the passed in signature algorithm name.
     *
     * @param algName the name of the signature algorithm of interest.
     * @return an algorithm identifier for the corresponding signature.
     */
    public AlgorithmIdentifier findAlgorithmByAlgorithmName(String algName)
    {
        AlgorithmIdentifier algorithmIdentifier;
        String algorithmName = Strings.toUpperCase(algName);
        ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier)IdentifiersConstants.algorithms.get(algorithmName);
        if (identifier == null)
        {
            throw new IllegalArgumentException("Unknown signature type requested: " + algorithmName);
        }

        if (IdentifiersConstants.noParams.contains(identifier))
        {
            algorithmIdentifier = new AlgorithmIdentifier(identifier);
        }
        else if (IdentifiersConstants.params.containsKey(algorithmName))
        {
            algorithmIdentifier = new AlgorithmIdentifier(identifier, (ASN1Encodable)IdentifiersConstants.params.get(algorithmName));
        }
        else
        {
            algorithmIdentifier = new AlgorithmIdentifier(identifier, DERNull.INSTANCE);
        }

        return algorithmIdentifier;
    }
}
