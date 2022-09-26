package com.stamp.platform.bean.bc.outputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentVerifier;

import java.io.OutputStream;

/**
 * @description: SignVerify
 * @date: 2022/9/8 13:57
 * @author: fanqie
 */
public class SignVerify implements ContentVerifier {
    private ELS_BcSignerOutputStream signerOutputStream;
    private AlgorithmIdentifier algorithm;

    public SignVerify(AlgorithmIdentifier algorithm, ELS_BcSignerOutputStream ELSBcSignerOutputStream) {
        this.algorithm = algorithm;
        this.signerOutputStream = ELSBcSignerOutputStream;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithm;
    }

    @Override
    public OutputStream getOutputStream() {
        if (signerOutputStream == null) {
            throw new IllegalStateException("verifier not initialised");
        }
        return this.signerOutputStream;
    }

    @Override
    public boolean verify(byte[] expected) {
        //TODO 验签
        return this.signerOutputStream.verify(expected);
    }
}