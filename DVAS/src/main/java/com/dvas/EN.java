package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class EN {
    private Element X; // 边缘节点 (EN) 的公钥

    public EN(Pairing pairing, Element P) {
        // 生成 EN 的公钥
        X = P.mulZn(pairing.getZr().newRandomElement()).getImmutable();
    }

    // 获取公钥 X
    public Element getX() {
        return X;
    }
}
