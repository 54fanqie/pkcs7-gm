package com.stamp.platform.bean.bc;

import com.stamp.platform.bean.bc.algorithm.SwAlgorithmIdentifierFinderProvider;
import com.stamp.platform.bean.bc.algorithm.SwBcDigestProvider;
import com.stamp.platform.bean.bc.algorithm.SwBcSignerProvider;
import com.stamp.platform.bean.bc.outputStream.SignVerify;
import com.stamp.platform.bean.bc.outputStream.SwBcSignerOutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestProvider;
import java.io.IOException;

/**
 *
 * @description: SWContentVerifierProviderBuilder
 * @date: 2022/8/31 15:56
 * @author: fanqie
 */
public class SwBcContentVerifierProviderBuilder {

    protected BcDigestProvider digestProvider;
    protected SwAlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider;
    protected SwBcSignerProvider bcSignerProvider;

    public SwBcContentVerifierProviderBuilder() {
        this.digestProvider = SwBcDigestProvider.INSTANCE;
        this.algorithmIdentifierFinderProvider = SwAlgorithmIdentifierFinderProvider.INSTAN;
        this.bcSignerProvider = SwBcSignerProvider.INSTANCE;
    }

    public ContentVerifierProvider build(final X509CertificateHolder holder) {
        return new ContentVerifierProvider() {
            @Override
            public boolean hasAssociatedCertificate() {
                return true;
            }

            @Override
            public X509CertificateHolder getAssociatedCertificate() {
                return holder;
            }

            @Override
            public ContentVerifier get(AlgorithmIdentifier algorithm) throws OperatorCreationException {
                try {
                    //签名算法标识
                    AsymmetricKeyParameter var2 = PublicKeyFactory.createKey(holder.getSubjectPublicKeyInfo());
                    SwBcSignerOutputStream var3 = createSignatureStream(algorithm, var2);
                    return new SignVerify(algorithm, var3);
                } catch (IOException var4) {
                    throw new OperatorCreationException("exception on setup: " + var4, var4);
                }
            }
        };
    }

    /**
     * 根据算法标识 确定签名实现类  摘要实现类
     */
    protected Signer createSigner(AlgorithmIdentifier sigAlgId) throws OperatorCreationException {
        //查找到与签名算法匹配的摘要算法标识符，获取摘要算法标识
        AlgorithmIdentifier digAlg = algorithmIdentifierFinderProvider.find(sigAlgId);
        //摘要类
        Digest dig = digestProvider.get(digAlg);
        String algName = algorithmIdentifierFinderProvider.getEncryptionAlgName(sigAlgId.getAlgorithm());
        Signer signer = this.bcSignerProvider.get(algName, dig);
        return signer;
    }

    /**
     * 创建签名类 steam
     */
    private SwBcSignerOutputStream createSignatureStream(AlgorithmIdentifier algorithm, AsymmetricKeyParameter keyParameter)
            throws OperatorCreationException {
        Signer sig = createSigner(algorithm);
        sig.init(false, keyParameter);
        return new SwBcSignerOutputStream(sig);
    }



}
