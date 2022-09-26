package com.stamp.platform.bean.bc;


import com.stamp.platform.PrivateUtil;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.Strings;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @description: SWSignatureAlgorithmIdentifierFinder
 * @date: 2022/9/2 14:34
 * @author: fanqie
 */
public class SWSignatureAlgorithmIdentifierFinder extends DefaultSignatureAlgorithmIdentifierFinder {

    private static Map algorithms = new HashMap();
    private static Set noParams = new HashSet();
    private static Map params = new HashMap();


    public SWSignatureAlgorithmIdentifierFinder() {
        super();
        //gm
//        addDigestAlgId(GMObjectIdentifiers.sm3, false);
        DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
        algorithms= (Map) PrivateUtil.getFieldValue(this.getClass(), finder, "algorithms");
        noParams= (Set) PrivateUtil.getFieldValue(this.getClass(), finder, "noParams");
        params= (Map) PrivateUtil.getFieldValue(this.getClass(), finder, "params");
    }

}
