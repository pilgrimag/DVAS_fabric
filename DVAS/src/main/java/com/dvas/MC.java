package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class MC {
    private Element s; // 私钥
    private Element S; // 公钥

    public MC(Pairing pairing, Element P) {
        // 主控制器 (MC) 的密钥生成
         s = pairing.getZr().newRandomElement().getImmutable(); // 随机选择 s ∈ Zq*
         S = P.mulZn(s).getImmutable(); // S = sP
    }
    

    // 获取公钥 S
    public Element getS() {
        return S;
    }

    // 获取私钥 s
    public Element getPrivateKey() {
        return s;
    }
}
