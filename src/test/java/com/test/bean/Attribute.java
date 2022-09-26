package com.stamp.platform.bean.pkcs7;

import org.bouncycastle.asn1.*;

/**
 *  用户认证属性
 * Attribute ::= SEQUENCE {
 *      type EncodedObjectID,
 *      values AttributeSetValue
 * }
 * @description: Attribute
 * @date: 2022/8/25 13:54
 * @author: fanqie
 */
public class Attribute extends ASN1Object {

    private ASN1ObjectIdentifier attrType;
    private ASN1Set attrValues;

    private Attribute(ASN1Sequence var1) {
        this.attrType = (ASN1ObjectIdentifier)var1.getObjectAt(0);
        this.attrValues = (ASN1Set)var1.getObjectAt(1);
    }

    public Attribute(ASN1ObjectIdentifier var1, ASN1Set var2) {
        this.attrType = var1;
        this.attrValues = var2;
    }

    public Attribute(ASN1ObjectIdentifier var1, ASN1Encodable obj) {
        this.attrType = var1;
        ASN1EncodableVector var2 = new ASN1EncodableVector(1);
        var2.add(obj);
        this.attrValues= new DERSet(var2);
    }


    public ASN1ObjectIdentifier getAttrType() {
        return this.attrType;
    }

    public ASN1Set getAttrValues() {
        return this.attrValues;
    }

    public ASN1Encodable[] getAttributeValues() {
        return this.attrValues.toArray();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector var1 = new ASN1EncodableVector(2);
        var1.add(this.attrType);
        var1.add(this.attrValues);
        return new DERSequence(var1);
    }
}
