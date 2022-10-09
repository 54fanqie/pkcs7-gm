package com.test;

import com.stamp.platform.Pkcs7Factory;
import com.stamp.platform.bean.pkcs7.SignedDataExt;
import com.stamp.platform.gm.SM2Util;
import com.stamp.platform.gm.SM3Util;
import com.stamp.platform.gm.rsa.SHADigest;
import com.stamp.platform.gm.rsa.Signers;
import com.stamp.platform.key.*;
import com.stamp.platform.util.*;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * @description: com.test.PkcsTest
 * @date: 2022/9/15 17:04
 * @author: fanqie
 */
public class PkcsTest {
    //公私钥
    private static String RSAPub = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100AB7AF730C7692FFD0E715E8E1992376254C02E6539800C8F90D196B71A3993A4E7C6ABD0621E577792D9236C58B9CD53E2E7D41A5834A5E99C8B2CB7467ED1F4767850ACE182E791E1F7FDE2F55FD414983DA5116FFDDA0D5929864BE93E76654AA9166411A5D70F4B5C536ECDF06A11A701EAA17D0D0279B8E6D16619C2C55F2DCA3B1D5C47A8148F4F0819ACC956622B05E2E1D5723384849157AD19A15C8835777BD121AA63918760B0442FACDB69FE76D8471A237CD0EC7EEA48AF30B838185725306A260AD79ED9714ACAEF0D5F2ED90F186844104D7EA750C044128DA709EDE9FF80A4149FFE367CD42FE254B43D80FB93AA73EBE5B47185D739DDBECB0203010001";
    private static String RSAPrav = "308204BE020100300D06092A864886F70D0101010500048204A8308204A40201000282010100AB7AF730C7692FFD0E715E8E1992376254C02E6539800C8F90D196B71A3993A4E7C6ABD0621E577792D9236C58B9CD53E2E7D41A5834A5E99C8B2CB7467ED1F4767850ACE182E791E1F7FDE2F55FD414983DA5116FFDDA0D5929864BE93E76654AA9166411A5D70F4B5C536ECDF06A11A701EAA17D0D0279B8E6D16619C2C55F2DCA3B1D5C47A8148F4F0819ACC956622B05E2E1D5723384849157AD19A15C8835777BD121AA63918760B0442FACDB69FE76D8471A237CD0EC7EEA48AF30B838185725306A260AD79ED9714ACAEF0D5F2ED90F186844104D7EA750C044128DA709EDE9FF80A4149FFE367CD42FE254B43D80FB93AA73EBE5B47185D739DDBECB020301000102820100155680C9DE1675B53C85D8E93FBF550AF456D1AF20DF91309029B462666E01B4446F115425D176BAD75813B358BB0E14C1286DD9355E9FC2990B2C6E45E46405D274183DDAF5EA10DA187CCC3012539698771B4237385458D2DE7AEA99447F810D304B2BFA923357A0DE0537C58284005C52BDBA889004DDD6A74A29354D6A37C0225F3288DDB328F6893E47EE3FF5D7A9131D29DD019A8329CEECC123F843489AD80EF73E243874DD44504F4C90CDE0D2AD8680ABEF9EB670E270F2073F6188D7CE55CE1AD05FFB6942F49DF05839CA44DE4E7B8F51889A9BEF6B3975DBA48AA462603339756E425D42F4240A9CF621F904CA7FE0B0478B00A7647FA9DBC70902818100EFAA09A1A2AD72DAEE56E4B1FD9CF526639892F8558550DDFF284D63F38681F25BBA06850A553496ECB58CBE667415D6A37F611C7BECF7EB051F4AE5B0A0837C5E7F80AF203CF961EC96850459A31F454F388B2112E9844349EB6775E1221D3E643D42EA6AAB88BDF900EDCAD390F83221C749ADF53757E6F7FEB5AE06E6F0FF02818100B72B2B85947D6BBB5963B943912A8E630576D9083A1868D386E209AFEF2817DDC3DEDD721A6D0DCB8E7B9FF8C72D951645E44F9343B388414C453A3A45EF749BCA311F137E01774D2971CB71532FCC7F0F5B18E49948579C7181F500E54E59CC396B523E3039A96DD2B09A162D1ABF64F8D33B4734766D076CEBB2B6B3B8263502818100878A5AB81710910C500EC478053E6746B6BCEB2196FC36A7D64E2CB6825B67D2711DDBE211DDEE480CC7003A0E2748D282D4DF4F04A717EECA8ED004E6C760954DBC3E42CCB0AF393A5C460E17C3B143B971F8FD537CCD5860CDC94D596DB9AC37748E0B95183DD572A59BD641A0933D86ECF63673A0410E56E2AE4D258A2671028181008E2F33AC90B4BF410245B8156C0565DC15ECC8D26B0E71A8E9866350AFCC26A29E1E4D35FAAF76CAF182A38E6146CFF9272DF05B776D50B2A77B0195249E999D2959F22E965C9AF849D8ACBCFE7F1735F67C9799342784E2CAF5BF72FF8D4F858978F6B1918BE12A802758A5284420184852E82C00DC810C078FFAFD7A0AD3950281801FBF5736A2039557D27302F29B0FEE55A9E823952DB8EC05A29B9D35A66026C266A5F8161D6186AF6FE3CFFCCA61C4AF740BE7EB1597A39F45C939617E343631827572C98E20466A2C0B5D0FD29608B8E03F54D576A728696347931FE04D19AFB698BCEA0CB6940DA076E26747343AFD834ACD75D192568C7AE4767777B0ED36";

    @Test
    public void creatPkcs7RSA() throws IOException {
        byte[] plant = "nsajnasnainsianisaisna".getBytes(StandardCharsets.UTF_8);
        //证书
        String cerString = ProjectPathUtil.resourceFileByLines(this.getClass(), "rsa实体证书.cer");
        byte[] certificate = PemUtil.readPemObject(cerString);
        //原文摘要
        byte[] hash = SHADigest.getSHA256(plant);
        IKeyHelper helper = KeyHelperManager.getByName("RSA");
        PrivateKey privateKey = helper.convertByteToPrivateKey(HexUtil.hexToByte(RSAPrav));

        //摘要算法标识
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        //方式一： 放认证属性，没有原文
        ASN1Set authenticatedAttributes = Pkcs7Factory.buildAuthenticatedAttributes(hash, digestAlgorithm);
        byte[] p7 = Pkcs7Factory.digitalSign(null, digestAlgorithm, certificate, authenticatedAttributes, indata -> {
            byte[] pbAuthedAttr = SHADigest.getSHA256(indata);
            return helper.sign(privateKey,pbAuthedAttr);
        });
        //方式二： 放原文摘要，没有认证属性
//        byte[] p7 = Pkcs7Factory4.genPKCS7(hash, digestAlgorithm, certificate ,null, indata -> helper.sign(indata, privateKey));
        //验证
        Pkcs7Factory.digitalSignVerify(plant, p7);
        FileUtils.writeFile(p7, "/Users/fanqie/Desktop/share/rsa_p7.dat");
        System.out.println(p7.length);

//        ASN1Sequence sequenceCreate = ASN1Sequence.getInstance(p7);
//        byte[] p7signdataRSA = ProjectPathUtil.resourceFileBytes(StartTest.class, "pkcs7/SignedValue-rsa.dat");
//        ASN1Sequence sequence2 = ASN1Sequence.getInstance(p7signdataRSA);
//        SWContentInfo cmsSingedData2 = new SWContentInfo(ContentInfo.getInstance(sequence));

    }

    private static final byte[] SM2_ID = {
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38,
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38
    };
    /**
     * sm2公钥私钥
     **/
    public static final String SM2PUB = "04A431FFF2DD4C5B19F23AAE58477959DFCE598CB78415D34AD13F5BDFC2792197FE34CE340C8F8B0C8243DCB1257B31866A61DDB3A6E20A53A86FBD0AC99D6805";
    public static final String SM2PRAV = "5BEA34A9526BE0E16D07721C8408D00FEB2A73757D42DF2D08DAD5000A5827BF";

    @Test
    public void creatPkcs7SM2() throws IOException {
        System.out.println("===========================组装PKCS7===============================");
        byte[] plant = "nsajnasnainsianisaisna".getBytes(StandardCharsets.UTF_8);
        //证书
        String cerString = ProjectPathUtil.resourceFileByLines(this.getClass(), "sm2证书.cer");
        byte[] certificate = PemUtil.readPemObject(cerString);
        //原文摘要
        byte[] plantHash = SM3Util.hash(plant);
        IKeyHelper helper = KeyHelperManager.getByName("SM2");
        PrivateKey privateKey = helper.convertByteToPrivateKey(HexUtil.hexToByte(SM2PRAV));
        PublicKey publicKey = helper.convertByteToPublicKey(HexUtil.hexToByte(SM2PUB));

        //摘要算法标识
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm3, DERNull.INSTANCE);
        //方式一： 放认证属性，没有原文
        ASN1Set authenticatedAttributes = Pkcs7Factory.buildAuthenticatedAttributes(plantHash, digestAlgorithm);

        byte[] p7 = Pkcs7Factory.digitalSign(null, digestAlgorithm, certificate, authenticatedAttributes, indata -> {
            //摘要一
            byte[] hashWithPub = SM3Util.hash(HexUtil.hexToByte(SM2PUB), indata);
            System.out.println("认证属性摘要带公钥=> " + HexUtil.byteToHex(hashWithPub));

            //摘要二
            byte[] pbAuthedAttr2 = SM3Util.hash(indata);
            System.out.println("认证属性裸摘 " + HexUtil.byteToHex(pbAuthedAttr2));

            //摘要三
            SM3Digest hahasm3Degist = new SM3Digest();
            hahasm3Degist.update(indata, 0, indata.length);
            byte[] pbAuthedAttr3 = new byte[32];
            hahasm3Degist.doFinal(pbAuthedAttr3, 0);
            System.out.println("认证属性裸摘 " + HexUtil.byteToHex(pbAuthedAttr3));


            byte[] clientSign = SM2Util.clientSign(HexUtil.hexToByte(SM2PRAV), indata, false);
            System.out.println("签名值 => " + HexUtil.byteToHex(clientSign));

            System.out.println("===================== 验证方式一 ：===================== ");
            boolean flag = Signers.SM2VerifySign(publicKey , indata, clientSign);
            System.out.println(flag ? "验证成功" : "验证失败");


            System.out.println("===================== 验证方式二 ：===================== ");
            byte[] signature = Signers.SM2Sign(privateKey , indata);
            boolean flag2 = Signers.SM2VerifySign(publicKey ,indata, signature);
            System.out.println(flag2 ? "验证成功" : "验证失败");

            HAHASM2Signer sm2Signer = new HAHASM2Signer();
            AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);
            ParametersWithID parametersWithID = new ParametersWithID(ecParam, SM2_ID);
            sm2Signer.init(false, parametersWithID);
            sm2Signer.update(indata, 0, indata.length);
            boolean flag3 = sm2Signer.verifySignature(signature);
            System.out.println(flag3 ? "验证成功" : "验证失败");

            return clientSign;
        });
        System.out.println("打印P7  " + HexUtil.byteToHex(p7));
        Pkcs7Factory.digitalSignVerify(plantHash, p7);
        //方式二： 放原文摘要，没有认证属性
//        byte[] p7 = Pkcs7Factory4.digitalSign(hash, digestAlgorithm, certificate ,null, indata -> helper.sign(indata, privateKey));
//        FileUtils.writeFile(p7, "/Users/fanqie/Desktop/share/sm2_p7.dat");
        System.out.println(p7.length);
    }

    public static void main(String[] args) {
        String a  ="MIIE6AYKKoEcz1UGAQQCAqCCBNgwggTUAgEBMQ4wDAYIKoEcz1UBgxEFADAwBgoqgRzPVQYBBAIBoCIEIOgSxQiRdnCXCIbzDKTFd7WESTruObhTxkuR9/lR3LIhoIIDfDCCA3gwggMcoAMCAQICECzpC4CCXmzqxgngH82HWqowDAYIKoEcz1UBg3UFADCBhzELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1YmVpMQ4wDAYDVQQHDAVXdWhhbjE7MDkGA1UECgwySHViZWkgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPIEx0ZC4xDDAKBgNVBAsMA0VDQzENMAsGA1UEAwwESEJDQTAeFw0xOTA4MjEwMTI3MTRaFw0yMDA4MjAwMTI3MTRaMG8xCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmuZbljJcxDzANBgNVBAcMBuatpuaxiTEYMBYGA1UECwwP6buE5YaI5Lq656S+5bGAMSQwIgYDVQQDDBvmuZbljJfnnIHljbDnq6DlubPlj7DmtYvor5UwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATj6pKu27eBnK6mc1zl/s8xC4YZ2qP/zF4S2l329VJeelEgvsolq6aWn8Zud6Ua1Z3v+23c38wHIuK09uKrG/cGo4IBfTCCAXkwHwYDVR0jBBgwFoAU9knnrFTTx/1tPRaTXOsoWePTQC0wDAYDVR0TBAUwAwEBADARBgVUEAsHAQQIDAYqMTY2QiowgekGA1UdHwSB4TCB3jA0oDKgMKQuMCwxCzAJBgNVBAYTAkNOMQwwCgYDVQQLDANDUkwxDzANBgNVBAMMBmNybDIzODAvoC2gK4YpaHR0cDovL3d3dy5oYmNhLm9yZy5jbi9jcmxfc20yL2NybDIzOC5jcmwwdaBzoHGGb2xkYXA6Ly8yMjEuMjMyLjIyNC43NDozODkvQ049Y3JsMjM4LE9VPUNSTCxDPUNOP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDAdBgUqVgsHAwQUExIxMjQxMTEwMTAwMDAwMDAwMDAwCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBTUI/Xk71fUoxUk1o8yUqtgs1gk6TAMBggqgRzPVQGDdQUAA0gAMEUCIQDIKkMrPLDNXF2NJqdj72JE86gdS/A9aYQujEU3AJpL/gIgPJvhaD0o3tbQ1KxB5I99GaPKtkpJDvQ3pCnHjcZVafcxggELMIIBBwIBATCBnDCBhzELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1YmVpMQ4wDAYDVQQHDAVXdWhhbjE7MDkGA1UECgwySHViZWkgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgQ2VudGVyIENPIEx0ZC4xDDAKBgNVBAsMA0VDQzENMAsGA1UEAwwESEJDQQIQLOkLgIJebOrGCeAfzYdaqjAMBggqgRzPVQGDEQUAMA0GCSqBHM9VAYItAQUABEYwRAIgSG9eeti/Cl2w5I6yMUL44e2MAfco63ekAsU/6oclv0kCIEDOyw5Nja3PoyEfqkGuHecUdSCfwSUo6rRvEzLrpgwQ";
        byte[] decode = Base64EnOrDe.decode(a);
        FileUtils.writeFile(decode,"/Users/fanqie/Desktop/gmpkcs7andPlain.dat");
    }

    //验证
    @Test
    public void verifyGomainPkcs7SM2() throws Exception {
        String a = "pkcs7/p7SignValue-bjca.dat";
        String b = "pkcs7/p7SignValue-GDCA.dat";
        String c = "pkcs7/p7SignValue-liaoning.dat";
        String d = "pkcs7/p7signdata.dat";
        String e = "pkcs7/gmpkcs7.dat";
        String f = "pkcs7/gmpkcs7andPlain.dat";
        byte[] p7signdata = ProjectPathUtil.resourceFileBytes(PkcsTest.class, f);

        ContentInfo swContentInfo = ContentInfo.getInstance(p7signdata);
        SignedDataExt signedData = SignedDataExt.getInstance(swContentInfo.getContent());

        Map<ASN1Integer, Certificate> serialNumberAndCert = signedData.getSerialNumberAndCert();

        signedData.getSignerInfoList().forEach(signerInfo -> {
            ASN1Integer serialNumber = signerInfo.getIssuerAndSerialNumber().getCertificateSerialNumber();
            Certificate certificate = serialNumberAndCert.get(serialNumber);
            X509CertificateHolder holder = new X509CertificateHolder(certificate);
            SubjectPublicKeyInfo subjectPublicKeyInfo = holder.getSubjectPublicKeyInfo();
            IKeyHelper helper = KeyHelperManager.getByName("SM2");
            PublicKey publikey = helper.convertToPublicKey(subjectPublicKeyInfo);
            byte[] signature = signerInfo.getSignature();
            byte[] authentiData = signerInfo.getAuthData();
            byte[] pub = helper.convertPublicKeyToByte(publikey);
            boolean flag3 = false;
            try {
//                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1,DERNull.INSTANCE);
//                flag3 = Signers.RSAVerifySign(publikey, authentiData, signature, algorithmIdentifier);
                flag3 = Signers.SM2VerifySign(publikey, authentiData, signature);
                System.out.println(flag3 ? "验证成功" : "验证失败");

                flag3 = SM2Util.clientVerifySign(pub,authentiData,signature,false);
                System.out.println(flag3 ? "验证成功" : "验证失败");
            } catch (Exception ee) {
                ee.printStackTrace();
            }

        });

    }

    //验证
    @Test
    public void verifyPkcs7Sign() throws Exception {
        IKeyHelper helper = KeyHelperManager.getByName("SM2");
        PublicKey publicKey = helper.convertByteToPublicKey(HexUtil.hexToByte(SM2PUB));
        byte[] plant = "nsajnasnainsianisaisna".getBytes(StandardCharsets.UTF_8);
        //认证属性原文
        byte[] pbAuthedAttr = HexUtil.hexToByte("316A301906092A864886F70D010903310C060A2A811CCF550601040201301C06092A864886F70D010905310F170D3232303833313136303030305A302F06092A864886F70D01090431220420B96F3DCCA4B227CB0ECB3617DE5A84D4694388E31DA7719D5E5B078D3F0240A8");
        byte[] hash = SM3Util.hash(pbAuthedAttr);
        System.out.println("认证属性摘要=> " + HexUtil.byteToHex(hash));

        byte[] hashWithPub = SM3Util.hash(HexUtil.hexToByte(SM2PUB), pbAuthedAttr);
        System.out.println("认证属性摘要带公钥=> " + HexUtil.byteToHex(hashWithPub));
        //认证属性摘要
        // 9A79353BF1E0309BA32148E824DA56394472CA39C90AAC3A569FF11E62E758E6
        //签名值
        byte[] sign = SM2Util.clientSign(HexUtil.hexToByte(SM2PRAV), hashWithPub, true);

        //验签
        boolean flag = Signers.SM2VerifySign(publicKey,pbAuthedAttr, sign);
        System.out.println(flag ? "成功" : "失败");
        //验签
        HAHASM2Signer sm2Signer = new HAHASM2Signer();
        AsymmetricKeyParameter ecParam = ECUtil.generatePublicKeyParameter(publicKey);
        ParametersWithID parametersWithID = new ParametersWithID(ecParam, SM2_ID);
        sm2Signer.init(false, parametersWithID);
        sm2Signer.update(pbAuthedAttr, 0, pbAuthedAttr.length);
        boolean flag2 = sm2Signer.verifySignature(sign);
        System.out.println(flag2 ? "成功" : "失败");


        byte[] p7 = HexUtil.hexToByte("30820323060A2A811CCF550601040202A08203133082030F020103310E300C06082A811CCF550183110500300C060A2A811CCF550601040201A08201CA308201C63082016CA00302010202086882B3BEA33141DD300A06082A811CCF550183753034310B300906035504061302434E310D300B06035504030C045454434131163014060355040A0C0D4341204D616E67657220736D32301E170D3232303831333038353130325A170D3332303831303038353030325A3039310D300B06035504030C045454434131123010060355040A0C094341204D616E67657231143012060355040B0C0B534D322D4341204F5554483059301306072A8648CE3D020106082A811CCF5501822D03420004A431FFF2DD4C5B19F23AAE58477959DFCE598CB78415D34AD13F5BDFC2792197FE34CE340C8F8B0C8243DCB1257B31866A61DDB3A6E20A53A86FBD0AC99D6805A3633061301D0603551D0E04160414576D636AA054D7A7C781D2124014EC01F15A65C7301F0603551D23041830168014A32D72FF169AD26299A865E20157D0F96AA77AF7300F0603551D130101FF040530030101FF300E0603551D0F0101FF040403020106300A06082A811CCF550183750348003045022100A7AAC90A3D9150D95F3D80BFDA5CA3542D122DF06E0E6CD1C02BC278AB24F67502206BFCB560A0CE1C505531DAA2B7B8D826D2863D83045272A12310E5218F4A53873182011C3082011802010130403034310B300906035504061302434E310D300B06035504030C045454434131163014060355040A0C0D4341204D616E67657220736D3202086882B3BEA33141DD300C06082A811CCF550183110500A06A301906092A864886F70D010903310C060A2A811CCF550601040201301C06092A864886F70D010905310F170D3232303833313136303030305A302F06092A864886F70D01090431220420B96F3DCCA4B227CB0ECB3617DE5A84D4694388E31DA7719D5E5B078D3F0240A8300D06092A811CCF5501822D01050004483046022100C094FFA1A80322D87BA0EF4F528849FC06FDB0730ECDFDED72E654C1CDF29F860221008F160E7583ED1D6CA897A6F90FC28D28DD7BAB445BD486FFA7AC60D530839211");
        Pkcs7Factory.digitalSignVerify(SM3Util.hash(plant), p7);
    }
}
