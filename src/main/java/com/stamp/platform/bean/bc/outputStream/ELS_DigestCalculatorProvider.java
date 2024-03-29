package com.stamp.platform.bean.bc.outputStream;

import com.stamp.platform.bean.bc.algorithm.ELS_BcDigestProvider;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestProvider;

import java.io.OutputStream;

/**
 * 摘要计算器
 * @description: SWDigestCalculatorProvider
 * @date: 2022/8/31 16:40
 * @author: fanqie
 */
public class ELS_DigestCalculatorProvider implements DigestCalculatorProvider {

    public static DigestCalculatorProvider INSTANCE = new ELS_DigestCalculatorProvider();
    private BcDigestProvider digestProvider = ELS_BcDigestProvider.INSTANCE;

    @Override
    public DigestCalculator get(AlgorithmIdentifier algorithm) throws OperatorCreationException {
        Digest dig = digestProvider.get(algorithm);
        final ELS_BcDigestOutputStream stream = new ELS_BcDigestOutputStream(dig);

        return new DigestCalculator()
        {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return algorithm;
            }

            @Override
            public OutputStream getOutputStream()
            {
                return stream;
            }

            @Override
            public byte[] getDigest()
            {
                return stream.getDigest();
            }
        };
    }



}
