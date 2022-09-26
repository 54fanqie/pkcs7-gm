package com.stamp.platform.bean.bc.constants;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @description: IdentifiersConstants
 * @date: 2022/9/6 17:14
 * @author: fanqie
 */
public class IdentifiersConstants {
    /**
     *
     * 签名算法  <OID，名称>
     */
    public static Map encryptionAndName = new HashMap();
    /**
     * 摘要算法  <OID，名称>
     */
    public static Map   digestOIDAndName = new HashMap();
    private static void addEntries(ASN1ObjectIdentifier alias, String digest, String encryption)
    {
        digestOIDAndName.put(alias, digest);
        encryptionAndName.put(alias, encryption);
    }
   static
    {
        addEntries(NISTObjectIdentifiers.dsa_with_sha224, "SHA224", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha256, "SHA256", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha384, "SHA384", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha512, "SHA512", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512", "DSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512", "RSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "SHA3-224", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "SHA3-256", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "SHA3-384", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "SHA3-512", "ECDSA");
        addEntries(OIWObjectIdentifiers.dsaWithSHA1, "SHA1", "DSA");
        addEntries(OIWObjectIdentifiers.md4WithRSA, "MD4", "RSA");
        addEntries(OIWObjectIdentifiers.md4WithRSAEncryption, "MD4", "RSA");
        addEntries(OIWObjectIdentifiers.md5WithRSA, "MD5", "RSA");
        addEntries(OIWObjectIdentifiers.sha1WithRSA, "SHA1", "RSA");
        addEntries(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2", "RSA");
        addEntries(PKCSObjectIdentifiers.md4WithRSAEncryption, "MD4", "RSA");
        addEntries(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5", "RSA");
        addEntries(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1", "RSA");
        addEntries(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224", "RSA");
        addEntries(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256", "RSA");
        addEntries(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512_224WithRSAEncryption, "SHA512(224)", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512_256WithRSAEncryption, "SHA512(256)", "RSA");

        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256", "RSA");

        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512", "ECDSA");
        addEntries(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1", "DSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
        addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160", "PLAIN-ECDSA");

//        addEntries(GMObjectIdentifiers.sm2sign_with_rmd160, "RIPEMD160", "SM2");
        //SHA1的SM2签名
        addEntries(GMObjectIdentifiers.sm2sign_with_sha1, "SHA1", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha224, "SHA224", "SM2");
//        SHA256的SM2签名
        addEntries(GMObjectIdentifiers.sm2sign_with_sha256, "SHA256", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha384, "SHA384", "SM2");
        //SHA512的SM2签名
        addEntries(GMObjectIdentifiers.sm2sign_with_sha512, "SHA512", "SM2");
        //SM3的SM2签名
        addEntries(GMObjectIdentifiers.sm2sign_with_sm3, "SM3", "SM2");

        encryptionAndName.put(X9ObjectIdentifiers.id_dsa, "DSA");
        encryptionAndName.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        encryptionAndName.put(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA");
        encryptionAndName.put(X509ObjectIdentifiers.id_ea_rsa, "RSA");
        encryptionAndName.put(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAandMGF1");
        encryptionAndName.put(CryptoProObjectIdentifiers.gostR3410_94, "GOST3410");
        encryptionAndName.put(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
        encryptionAndName.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
        encryptionAndName.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
        encryptionAndName.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
        encryptionAndName.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
        encryptionAndName.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
        encryptionAndName.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");
        encryptionAndName.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256");
        encryptionAndName.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512");
        //SM2椭 圆曲线公钥 密码算法
        encryptionAndName.put(GMObjectIdentifiers.sm2p256v1,  "SM2");
        //数字签名算法
        encryptionAndName.put(GMObjectIdentifiers.sm2sign,  "SM2");



        digestOIDAndName.put(PKCSObjectIdentifiers.md2, "MD2");
        digestOIDAndName.put(PKCSObjectIdentifiers.md4, "MD4");
        digestOIDAndName.put(PKCSObjectIdentifiers.md5, "MD5");
        digestOIDAndName.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha512_224, "SHA512(224)");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha512_256, "SHA512(256)");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        digestOIDAndName.put(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        digestOIDAndName.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        digestOIDAndName.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        digestOIDAndName.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        digestOIDAndName.put(CryptoProObjectIdentifiers.gostR3411,  "GOST3411");
        digestOIDAndName.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"),  "GOST3411");
        digestOIDAndName.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,  "GOST3411-2012-256");
        digestOIDAndName.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,  "GOST3411-2012-512");
        // SM3 密码杂凑算法
        digestOIDAndName.put(GMObjectIdentifiers.sm3,  "SM3");
        // SM3 密码杂凑算法 无秘钥使用
        digestOIDAndName.put(GMObjectIdentifiers.sm3.branch("1"),  "SM3");
        // SM3 密码杂凑算法 有秘钥使用
        digestOIDAndName.put(GMObjectIdentifiers.sm3.branch("2"),  "SM3");



    }



    /**
     *
     * 混合算法oid 转 摘要算法oid
     */
    public static Map aToDigestOids = new HashMap();
    /**
     *
     * 根据oid 获取算法标识 <oid,算法标识>
     */
    public static Map digestOidToAlgIds = new HashMap();
    /**
     *
     *  <算法名称,算法oid>
     */
    public static Map algorithms = new HashMap();
    /**
     *
     * 无Param项的算法oid 集合
     */
    public static Set noParams = new HashSet();
    /**
     *
     * 特殊对象RSASSAPSSparams 的算法oid 集合
     * see :<@link org.bouncycastle.asn1.x509.AlgorithmIdentifier>
     */
    public static Map params = new HashMap();

    // 根据合成oid 查找对应的摘要oid 如： sm3withsm2  为501  摘要算法为 301
    static
    {
        // digests
        aToDigestOids.put(OIWObjectIdentifiers.dsaWithSHA1, OIWObjectIdentifiers.idSHA1);
        aToDigestOids.put(OIWObjectIdentifiers.md4WithRSAEncryption, PKCSObjectIdentifiers.md4);
        aToDigestOids.put(OIWObjectIdentifiers.md4WithRSA, PKCSObjectIdentifiers.md4);
        aToDigestOids.put(OIWObjectIdentifiers.sha1WithRSA, OIWObjectIdentifiers.idSHA1);

        aToDigestOids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        aToDigestOids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        aToDigestOids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        aToDigestOids.put(PKCSObjectIdentifiers.sha512_224WithRSAEncryption, NISTObjectIdentifiers.id_sha512_224);
        aToDigestOids.put(PKCSObjectIdentifiers.sha512_256WithRSAEncryption, NISTObjectIdentifiers.id_sha512_256);
        aToDigestOids.put(PKCSObjectIdentifiers.md2WithRSAEncryption, PKCSObjectIdentifiers.md2);
        aToDigestOids.put(PKCSObjectIdentifiers.md4WithRSAEncryption, PKCSObjectIdentifiers.md4);
        aToDigestOids.put(PKCSObjectIdentifiers.md5WithRSAEncryption, PKCSObjectIdentifiers.md5);
        aToDigestOids.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, OIWObjectIdentifiers.idSHA1);

        aToDigestOids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, OIWObjectIdentifiers.idSHA1);
        aToDigestOids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, NISTObjectIdentifiers.id_sha256);
        aToDigestOids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, NISTObjectIdentifiers.id_sha384);
        aToDigestOids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, NISTObjectIdentifiers.id_sha512);
        aToDigestOids.put(X9ObjectIdentifiers.id_dsa_with_sha1, OIWObjectIdentifiers.idSHA1);

        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, OIWObjectIdentifiers.idSHA1);
        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, NISTObjectIdentifiers.id_sha256);
        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, NISTObjectIdentifiers.id_sha384);
        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, NISTObjectIdentifiers.id_sha512);
        aToDigestOids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, TeleTrusTObjectIdentifiers.ripemd160);

        aToDigestOids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, OIWObjectIdentifiers.idSHA1);
        aToDigestOids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, NISTObjectIdentifiers.id_sha256);
        aToDigestOids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, NISTObjectIdentifiers.id_sha384);
        aToDigestOids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, NISTObjectIdentifiers.id_sha512);

        aToDigestOids.put(NISTObjectIdentifiers.dsa_with_sha224, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(NISTObjectIdentifiers.dsa_with_sha256, NISTObjectIdentifiers.id_sha256);
        aToDigestOids.put(NISTObjectIdentifiers.dsa_with_sha384, NISTObjectIdentifiers.id_sha384);
        aToDigestOids.put(NISTObjectIdentifiers.dsa_with_sha512, NISTObjectIdentifiers.id_sha512);

        aToDigestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        aToDigestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        aToDigestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        aToDigestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        aToDigestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        aToDigestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        aToDigestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        aToDigestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        aToDigestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        aToDigestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        aToDigestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        aToDigestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);

        aToDigestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers.ripemd128);
        aToDigestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers.ripemd160);
        aToDigestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers.ripemd256);

        aToDigestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers.gostR3411);
        aToDigestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers.gostR3411);
        aToDigestOids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        aToDigestOids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

        aToDigestOids.put(BCObjectIdentifiers.sphincs256_with_SHA3_512, NISTObjectIdentifiers.id_sha3_512);
        aToDigestOids.put(BCObjectIdentifiers.sphincs256_with_SHA512, NISTObjectIdentifiers.id_sha512);

//        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.ripemd160);
//        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sha1, OIWObjectIdentifiers.idSHA1);
//        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sha224, NISTObjectIdentifiers.id_sha224);
        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sha256, NISTObjectIdentifiers.id_sha256);
//        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sha384, NISTObjectIdentifiers.id_sha384);
//        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sha512, NISTObjectIdentifiers.id_sha512);
        aToDigestOids.put(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);

        aToDigestOids.put(CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128, NISTObjectIdentifiers.id_shake128);
        aToDigestOids.put(CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE256, NISTObjectIdentifiers.id_shake256);
        aToDigestOids.put(CMSObjectIdentifiers.id_ecdsa_with_shake128, NISTObjectIdentifiers.id_shake128);
        aToDigestOids.put(CMSObjectIdentifiers.id_ecdsa_with_shake256, NISTObjectIdentifiers.id_shake256);




        //数据填充，部分标识含有params 部分不包含
        // IETF RFC 3370
        addDigestAlgId(OIWObjectIdentifiers.idSHA1, true);
        // IETF RFC 5754
        addDigestAlgId(NISTObjectIdentifiers.id_sha224, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha256, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha384, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha512, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha512_224, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha512_256, false);

        // NIST CSOR
        addDigestAlgId(NISTObjectIdentifiers.id_sha3_224, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha3_256, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha3_384, false);
        addDigestAlgId(NISTObjectIdentifiers.id_sha3_512, false);

        // RFC 8702
        addDigestAlgId(NISTObjectIdentifiers.id_shake128, false);
        addDigestAlgId(NISTObjectIdentifiers.id_shake256, false);

        // RFC 4357
        addDigestAlgId(CryptoProObjectIdentifiers.gostR3411, true);

        // draft-deremin-rfc4491
        addDigestAlgId(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, false);
        addDigestAlgId(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, false);

        // IETF RFC 1319
        addDigestAlgId(PKCSObjectIdentifiers.md2, true);
        // IETF RFC 1320
        addDigestAlgId(PKCSObjectIdentifiers.md4, true);
        // IETF RFC 1321
        addDigestAlgId(PKCSObjectIdentifiers.md5, true);

        // found no standard which specified the handle of AlgorithmIdentifier.parameters,
        // so let it as before.
        addDigestAlgId(TeleTrusTObjectIdentifiers.ripemd128, true);
        addDigestAlgId(TeleTrusTObjectIdentifiers.ripemd160, true);
        addDigestAlgId(TeleTrusTObjectIdentifiers.ripemd256, true);
    }

    //算法oid 集合
    static {
        //
        // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
        // The parameters field SHALL be NULL for RSA based signature algorithms.
        //
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(OIWObjectIdentifiers.dsaWithSHA1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha384);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_512);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_512);

        //
        // RFC 4491
        //
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        noParams.add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        noParams.add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

        //
        // SPHINCS-256
        //
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);

        //
        // XMSS
        //
        noParams.add(BCObjectIdentifiers.xmss_SHA256ph);
        noParams.add(BCObjectIdentifiers.xmss_SHA512ph);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE128ph);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE256ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA256ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA512ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        noParams.add(BCObjectIdentifiers.xmss_SHA256);
        noParams.add(BCObjectIdentifiers.xmss_SHA512);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE128);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE256);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA256);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA512);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE128);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE256);

        noParams.add(IsaraObjectIdentifiers.id_alg_xmss);
        noParams.add(IsaraObjectIdentifiers.id_alg_xmssmt);

        //
        // qTESLA
        //
        noParams.add(BCObjectIdentifiers.qTESLA_p_I);
        noParams.add(BCObjectIdentifiers.qTESLA_p_III);

        //
        // SM2
        //
//        noParams.add(GMObjectIdentifiers.sm2sign_with_rmd160);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha1);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha224);
        noParams.add(GMObjectIdentifiers.sm2sign_with_sha256);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha384);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha512);
        noParams.add(GMObjectIdentifiers.sm2sign_with_sm3);

        // EdDSA
        noParams.add(EdECObjectIdentifiers.id_Ed25519);
        noParams.add(EdECObjectIdentifiers.id_Ed448);

        // RFC 8702
        noParams.add(CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
        noParams.add(CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
        noParams.add(CMSObjectIdentifiers.id_ecdsa_with_shake128);
        noParams.add(CMSObjectIdentifiers.id_ecdsa_with_shake256);



    }
    //根据算法名称  得到算法标识
    static {
        //根据名称查找 摘要算法标识
        //摘要的
        algorithms.put("SHA-1", OIWObjectIdentifiers.idSHA1);
        algorithms.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        algorithms.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        algorithms.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        algorithms.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        algorithms.put("SHA-512-224", NISTObjectIdentifiers.id_sha512_224);
        algorithms.put("SHA-512-256", NISTObjectIdentifiers.id_sha512_256);
        algorithms.put("SHA1", OIWObjectIdentifiers.idSHA1);
        algorithms.put("SHA224", NISTObjectIdentifiers.id_sha224);
        algorithms.put("SHA256", NISTObjectIdentifiers.id_sha256);
        algorithms.put("SHA384", NISTObjectIdentifiers.id_sha384);
        algorithms.put("SHA512", NISTObjectIdentifiers.id_sha512);
        algorithms.put("SHA512-224", NISTObjectIdentifiers.id_sha512_224);
        algorithms.put("SHA512-256", NISTObjectIdentifiers.id_sha512_256);
        algorithms.put("SHA3-224", NISTObjectIdentifiers.id_sha3_224);
        algorithms.put("SHA3-256", NISTObjectIdentifiers.id_sha3_256);
        algorithms.put("SHA3-384", NISTObjectIdentifiers.id_sha3_384);
        algorithms.put("SHA3-512", NISTObjectIdentifiers.id_sha3_512);
        algorithms.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        algorithms.put("SHAKE256", NISTObjectIdentifiers.id_shake256);
        algorithms.put("SHAKE-128", NISTObjectIdentifiers.id_shake128);
        algorithms.put("SHAKE-256", NISTObjectIdentifiers.id_shake256);
        algorithms.put("GOST3411", CryptoProObjectIdentifiers.gostR3411);
        algorithms.put("GOST3411-2012-256", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        algorithms.put("GOST3411-2012-512", RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);
        algorithms.put("MD2", PKCSObjectIdentifiers.md2);
        algorithms.put("MD4", PKCSObjectIdentifiers.md4);
        algorithms.put("MD5", PKCSObjectIdentifiers.md5);
        algorithms.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        algorithms.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        algorithms.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);
        algorithms.put("SM3", GMObjectIdentifiers.sm3);
        //签名的
        algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512(224)WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        algorithms.put("SHA512(224)WITHRSA", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        algorithms.put("SHA512(256)WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
        algorithms.put("SHA512(256)WITHRSA", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
        algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384);
        algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512);
        algorithms.put("SHA3-224WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_224);
        algorithms.put("SHA3-256WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_256);
        algorithms.put("SHA3-384WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_384);
        algorithms.put("SHA3-512WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_512);
        algorithms.put("SHA3-224WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        algorithms.put("SHA3-256WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        algorithms.put("SHA3-384WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        algorithms.put("SHA3-512WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
        algorithms.put("SHA3-224WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        algorithms.put("SHA3-256WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        algorithms.put("SHA3-384WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        algorithms.put("SHA3-512WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        algorithms.put("SHA3-224WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        algorithms.put("SHA3-256WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        algorithms.put("SHA3-384WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        algorithms.put("SHA3-512WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411-2012-256WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411-2012-512WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
        algorithms.put("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA224);
        algorithms.put("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA256);
        algorithms.put("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA384);
        algorithms.put("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA512);
        algorithms.put("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        algorithms.put("SHA1WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
        algorithms.put("SHA224WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
        algorithms.put("SHA256WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
        algorithms.put("SHA384WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
        algorithms.put("SHA512WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);
        algorithms.put("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512);
        algorithms.put("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512);

        algorithms.put("ED25519", EdECObjectIdentifiers.id_Ed25519);
        algorithms.put("ED448", EdECObjectIdentifiers.id_Ed448);

        // RFC 8702
        algorithms.put("SHAKE128WITHRSAPSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
        algorithms.put("SHAKE256WITHRSAPSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
        algorithms.put("SHAKE128WITHRSASSA-PSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128);
        algorithms.put("SHAKE256WITHRSASSA-PSS", CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE256);
        algorithms.put("SHAKE128WITHECDSA", CMSObjectIdentifiers.id_ecdsa_with_shake128);
        algorithms.put("SHAKE256WITHECDSA", CMSObjectIdentifiers.id_ecdsa_with_shake256);

//        algorithms.put("RIPEMD160WITHSM2", GMObjectIdentifiers.sm2sign_with_rmd160);
//        algorithms.put("SHA1WITHSM2", GMObjectIdentifiers.sm2sign_with_sha1);
//        algorithms.put("SHA224WITHSM2", GMObjectIdentifiers.sm2sign_with_sha224);
        algorithms.put("SHA256WITHSM2", GMObjectIdentifiers.sm2sign_with_sha256);
//        algorithms.put("SHA384WITHSM2", GMObjectIdentifiers.sm2sign_with_sha384);
//        algorithms.put("SHA512WITHSM2", GMObjectIdentifiers.sm2sign_with_sha512);
        algorithms.put("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3);

        algorithms.put("SHA256WITHXMSS", BCObjectIdentifiers.xmss_SHA256ph);
        algorithms.put("SHA512WITHXMSS", BCObjectIdentifiers.xmss_SHA512ph);
        algorithms.put("SHAKE128WITHXMSS", BCObjectIdentifiers.xmss_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSS", BCObjectIdentifiers.xmss_SHAKE256ph);

        algorithms.put("SHA256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA256ph);
        algorithms.put("SHA512WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA512ph);
        algorithms.put("SHAKE128WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        algorithms.put("SHA256WITHXMSS-SHA256", BCObjectIdentifiers.xmss_SHA256ph);
        algorithms.put("SHA512WITHXMSS-SHA512", BCObjectIdentifiers.xmss_SHA512ph);
        algorithms.put("SHAKE128WITHXMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256ph);

        algorithms.put("SHA256WITHXMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256ph);
        algorithms.put("SHA512WITHXMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512ph);
        algorithms.put("SHAKE128WITHXMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        algorithms.put("LMS", PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

        algorithms.put("XMSS", IsaraObjectIdentifiers.id_alg_xmss);
        algorithms.put("XMSS-SHA256", BCObjectIdentifiers.xmss_SHA256);
        algorithms.put("XMSS-SHA512", BCObjectIdentifiers.xmss_SHA512);
        algorithms.put("XMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128);
        algorithms.put("XMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256);

        algorithms.put("XMSSMT", IsaraObjectIdentifiers.id_alg_xmssmt);
        algorithms.put("XMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256);
        algorithms.put("XMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512);
        algorithms.put("XMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128);
        algorithms.put("XMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256);

        algorithms.put("QTESLA-P-I", BCObjectIdentifiers.qTESLA_p_I);
        algorithms.put("QTESLA-P-III", BCObjectIdentifiers.qTESLA_p_III);


    }

    static {
        // 特殊 RSASSAPSSparams
        // explicit params
        //
        AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        params.put("SHA1WITHRSAANDMGF1", createPSSParams(sha1AlgId, 20));

        AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE);
        params.put("SHA224WITHRSAANDMGF1", createPSSParams(sha224AlgId, 28));

        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        params.put("SHA256WITHRSAANDMGF1", createPSSParams(sha256AlgId, 32));

        AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        params.put("SHA384WITHRSAANDMGF1", createPSSParams(sha384AlgId, 48));

        AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        params.put("SHA512WITHRSAANDMGF1", createPSSParams(sha512AlgId, 64));

        AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_224, DERNull.INSTANCE);
        params.put("SHA3-224WITHRSAANDMGF1", createPSSParams(sha3_224AlgId, 28));

        AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256, DERNull.INSTANCE);
        params.put("SHA3-256WITHRSAANDMGF1", createPSSParams(sha3_256AlgId, 32));

        AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_384, DERNull.INSTANCE);
        params.put("SHA3-384WITHRSAANDMGF1", createPSSParams(sha3_384AlgId, 48));

        AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_512, DERNull.INSTANCE);
        params.put("SHA3-512WITHRSAANDMGF1", createPSSParams(sha3_512AlgId, 64));
    }
    private static RSASSAPSSparams createPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
    {
        return new RSASSAPSSparams(
                hashAlgId,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId),
                new ASN1Integer(saltSize),
                new ASN1Integer(1));
    }
    private static void addDigestAlgId(ASN1ObjectIdentifier oid, boolean withNullParams)
    {
        AlgorithmIdentifier algId;
        if (withNullParams)
        {
            algId = new AlgorithmIdentifier(oid, DERNull.INSTANCE);
        }
        else
        {
            algId = new AlgorithmIdentifier(oid);
        }
        digestOidToAlgIds.put(oid, algId);
    }
}
