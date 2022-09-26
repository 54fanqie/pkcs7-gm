package com.stamp.platform.bean.bc;

import com.stamp.platform.bean.bc.algorithm.SwAlgorithmIdentifierFinderProvider;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.*;

/**
 * @description: SwSignerInformationVerifier
 * @date: 2022/9/6 16:15
 * @author: fanqie
 */
public class SwSignerInformationVerifier {
    private ContentVerifierProvider verifierProvider;
    private DigestCalculatorProvider digestProvider;
    private SwAlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider;


    public SwSignerInformationVerifier(SwAlgorithmIdentifierFinderProvider algorithmIdentifierFinderProvider , ContentVerifierProvider contentVerifierProvider, DigestCalculatorProvider digestProvider)
    {
        this.algorithmIdentifierFinderProvider = algorithmIdentifierFinderProvider;
        this.verifierProvider = contentVerifierProvider;
        this.digestProvider = digestProvider;
    }

    public boolean hasAssociatedCertificate()
    {
        return verifierProvider.hasAssociatedCertificate();
    }

    public X509CertificateHolder getAssociatedCertificate()
    {
        return verifierProvider.getAssociatedCertificate();
    }

    public ContentVerifier getContentVerifier(AlgorithmIdentifier signingAlgorithm, AlgorithmIdentifier digestAlgorithm)
            throws OperatorCreationException
    {
        String              signatureName = algorithmIdentifierFinderProvider.getSignatureName(digestAlgorithm, signingAlgorithm);
        AlgorithmIdentifier baseAlgID = algorithmIdentifierFinderProvider.findAlgorithmByAlgorithmName(signatureName);

        return verifierProvider.get(new AlgorithmIdentifier(baseAlgID.getAlgorithm(), signingAlgorithm.getParameters()));
    }

    public DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier)
            throws OperatorCreationException
    {
        return digestProvider.get(algorithmIdentifier);
    }
}
