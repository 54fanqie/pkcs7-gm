package com.stamp.platform.bean.bc.algorithm;

import com.stamp.platform.PrivateUtil;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.operator.bc.BcDigestProvider;

import java.util.HashMap;
import java.util.Map;

/**
 * 摘要算法构建类
 * @description: SwBcDigestProvider
 * @date: 2022/9/7 15:21
 * @author: fanqie
 */
public class SwBcDigestProvider implements BcDigestProvider {
    public static final    BcDigestProvider INSTANCE = new SwBcDigestProvider();

    private static Map table;
    public SwBcDigestProvider() {
        BcDigestProvider digestProvider = BcDefaultDigestProvider.INSTANCE;
        Map lookup =  (Map) PrivateUtil.getFieldValueCurrent(BcDefaultDigestProvider.class, digestProvider, "lookup");
        table = new HashMap<>();
        table.putAll(lookup);
        table.put(GMObjectIdentifiers.sm3, new BcDigestProvider() {
            @Override
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SM3Digest();
            }
        });
    }

    @Override
    public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            throws OperatorCreationException {
        BcDigestProvider extProv = (BcDigestProvider) table.get(digestAlgorithmIdentifier.getAlgorithm());

        if (extProv == null) {
            throw new OperatorCreationException("cannot recognise digest");
        }

        return extProv.get(digestAlgorithmIdentifier);
    }
}
