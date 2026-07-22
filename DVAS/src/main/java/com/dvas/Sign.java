package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
// import it.unisa.dia.gas.jpbc.PairingParameters;
// import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
// import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
// import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

// import java.util.HashMap;
// import java.util.HashSet;
// import java.util.Map;
// import java.util.Set;

// import com.dvas.Setup;

public class Sign {
    public Pairing pairing;
    private Setup setup;
    private SensorKeyPair sensorKeyPair; // 传感器密钥对

    // 构造方法注入 Setup 的 pairing
    public Sign(Setup setup) {
        this.pairing = setup.pairing;
    }

    public Sign(Setup setup, SensorKeyPair sensorKeyPair) {
        this.setup = setup;
        this.pairing = setup.pairing;
        this.sensorKeyPair = sensorKeyPair;
    }

    /**
     * 签名生成过程：感知节点生成签名。
     * @param M 传感器采集的数据
     * @param omega_i 授权协议
     * @param id 传感器ID
     * @param X 系统参数 (edgeNodeKey.getU_i())
     * @param Y 系统参数 (dvNodeKey.getU_i())
     * @return 返回生成的完整签名 σ_i = (T_i, V_i, Φ_i, id)
     */
    public Signature generateSignature(Message M, String omega_i, int id, Element X, Element Y) {
        if (pairing == null) {
            throw new RuntimeException("pairing is null. Check if it is properly initialized.");
        }
        Field<Element> zrField = pairing.getZr();
        if (zrField == null) {
            throw new RuntimeException("pairing.getZr() returned null. Check the parameter file.");
        }
        String m_i = M.getM();

        // 1. 随机选择一个数 v_i ∈ Z_q^*
        Element v_i = zrField.newRandomElement().getImmutable();

        // 2. 计算 V_i = v_i * P，其中 P 是系统的生成元
        Element V_i = setup.getP().duplicate().mulZn(v_i).getImmutable();

        // 3. 计算哈希值 t_i = h(m_i, ω_i, e(X, Y)^{u_i})
        Element eXY = pairing.pairing(X, Y).getImmutable();
        Element t_i = setup.H(m_i, omega_i, eXY.powZn(sensorKeyPair.getu_i()));

        // 4. 计算部分签名 Φ_i = u_i * t_i * Y
        Element Phi_i = Y.duplicate().mulZn(t_i).mulZn(sensorKeyPair.getu_i());

        // 5. !!! 以下是原代码中与区块链/外部通信相关，现已删除/注释掉的部分 !!!
        // sensorMap.put(sensorKeyPair.getU_i(), Phi_i);
        // blockchain.addSensorMap(sensorMap);

        // 6. 计算辅助哈希值 H_{0i} 和 H_{1i}
        Element H0_i = setup.H0(m_i, V_i, Phi_i);
        Element H1_i = setup.H1(m_i, V_i, Phi_i);

        // 7. 计算完整签名的一部分 T_i = u_i * H0_i + v_i * H1_i
        Element T_i = H0_i.duplicate().mulZn(sensorKeyPair.getu_i()).add(H1_i.duplicate().mulZn(v_i)).getImmutable();

        // !!! 以下是原代码中与 sendObj 相关的部分，现已删除/注释掉 !!!
        // sendObj.setT_i(T_i);
        // sendObj.setV_i(V_i);
        // sendObj.setm_i(M);
        // sendObj.setid(id);

        // 8. 返回完整签名 σ_i = (T_i, V_i, Φ_i, id)
        return new Signature(T_i, V_i, Phi_i, id);
    }

    // !!! 删除了 uploadSignature, uploadToBlockchain, uploadToEdgeNode 方法 !!!
    // 这些方法现在由 Main.java 直接处理或不再需要。

    /**
     * 签名的表示结构。
     */
    public static class Signature {
        private Element T_i; // 签名的 T_i 部分
        private Element V_i; // 随机生成的点 V_i
        private Element Phi_i; // 部分签名 Φ_i
        private int id;

        public Signature(Element T_i, Element V_i, Element Phi_i, int id) {
            this.T_i = T_i;
            this.V_i = V_i;
            this.Phi_i = Phi_i;
            this.id = id;
        }

        public Element getT_i() {
            return T_i;
        }

        public Element getV_i() {
            return V_i;
        }

        public Element getPhi_i() {
            return Phi_i;
        }

        public int getId(){
            return id;
        }

        public void setT_i(Element T_i) {
            this.T_i =  T_i;
        }

        public void setV_i(Element V_i) {
            this.V_i = V_i;
        }

        public void setPhi_i(Element Phi_i) {
            this.Phi_i = Phi_i;
        }
    }
}