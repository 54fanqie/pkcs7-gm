package com.test.bean;


import com.stamp.platform.util.PrivateUtil;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

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
