package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class DV {
    private Element Y; // 数据验证节点 (DV) 的公钥

    public DV(Pairing pairing, Element P) {
        // 生成 DV 的公钥
        Y = P.mulZn(pairing.getZr().newRandomElement()).getImmutable();
    }

    // 获取公钥 Y
    public Element getY() {
        return Y;
    }
}
