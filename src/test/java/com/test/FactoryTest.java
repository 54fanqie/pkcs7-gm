package com.test;

import com.stamp.platform.Pkcs7Factory;
import com.stamp.platform.gm.SM2Util;
import com.stamp.platform.gm.SM3Util;
import com.stamp.platform.key.IKeyHelper;
import com.stamp.platform.key.KeyHelperManager;
import com.stamp.platform.util.HexUtil;
import com.stamp.platform.util.PemUtil;
import com.stamp.platform.util.ProjectPathUtil;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @description: FactoryTest
 * @date: 2022/9/26 13:55
 * @author: fanqie
 */
public class FactoryTest {

    /**
     * sm2公钥私钥
     **/
    public static final String SM2PUB = "04A431FFF2DD4C5B19F23AAE58477959DFCE598CB78415D34AD13F5BDFC2792197FE34CE340C8F8B0C8243DCB1257B31866A61DDB3A6E20A53A86FBD0AC99D6805";
    public static final String SM2PRAV = "5BEA34A9526BE0E16D07721C8408D00FEB2A73757D42DF2D08DAD5000A5827BF";

    @Test
    public void test(){
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
            byte[] clientSign = SM2Util.clientSign(HexUtil.hexToByte(SM2PRAV), indata, false);
            System.out.println("签名值 => " + HexUtil.byteToHex(clientSign));
            return clientSign;
        });
        boolean verify = Pkcs7Factory.digitalSignVerify(plantHash, p7);
        System.out.println(verify ? "验证成功" : "验证失败");
        //方式二： 放原文摘要，没有认证属性
//        byte[] p7 = Pkcs7Factory4.digitalSign(hash, digestAlgorithm, certificate ,null, indata -> helper.sign(indata, privateKey));
//        FileUtils.writeFile(p7, "/Users/fanqie/Desktop/share/sm2_p7.dat");
        System.out.println(p7.length);
    }
}
