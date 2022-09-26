package com.stamp.platform.bean.bc.algorithm;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.operator.OperatorCreationException;

import java.util.Locale;

/**
 * 签名算法构建类
 * @description: SwBcSignerProvider
 * @date: 2022/9/8 11:14
 * @author: fanqie
 */
public class ELS_BcSignerProvider {
    public static final ELS_BcSignerProvider INSTANCE = new ELS_BcSignerProvider();
    public Signer get(String signatureName, Digest digest)
            throws OperatorCreationException {
        //根据算法标识 确定签名实现类
        if (signatureName.toUpperCase(Locale.ROOT).equals("SM2")) {
            return new SM2Signer(digest);
        } else {
            return new RSADigestSigner(digest);
        }
    }
}
