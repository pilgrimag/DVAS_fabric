package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.List;

// 不需要 MessageDigest 和 NoSuchAlgorithmException，因为 fmod 被注释掉了
// import java.security.MessageDigest;
// import java.security.NoSuchAlgorithmException;

import com.dvas.Setup;

public class SanitizingStage {

    private Pairing pairing;
    private Setup setup;

    public SanitizingStage(Setup setup) {
        this.pairing = setup.pairing;
        this.setup = setup; // 确保 setup 成员变量被初始化
    }

    // 新增一个内部类来存储细分时间，作为 verifySignature 的返回类型
    public static class SanitizingSubTimings {
        public long offChainComputeTime; // 纯链下密码学计算时间 (纳秒)
        public long fabricQueryTime;     // Fabric 链码查询时间 (纳秒)
        public boolean result;           // 验证结果

        public SanitizingSubTimings(long offChainComputeTime, long fabricQueryTime, boolean result) {
            this.offChainComputeTime = offChainComputeTime;
            this.fabricQueryTime = fabricQueryTime;
            this.result = result;
        }
    }


    // 验证数据签名
    // 修改返回类型为 SanitizingSubTimings
    public SanitizingSubTimings verifySignature(Setup setup, Element publicKey, List<Element> UPK, Element X, Message message, com.dvas.Sign.Signature signature, Element P, Element Y, Blockchain blockchain, List<Integer> ADM) {
        long currentOffChainComputeTime = 0; // 用于累加纯链下计算时间
        long currentFabricQueryTime = 0;     // 用于累加 Fabric 查询时间

        String data = message.getM();
        // 检查 publicKey 是否存在于 UPK 中
        if (!UPK.contains(publicKey)) { // 简化条件判断，如果不存在，直接打印
            System.out.println("publicKey does not exist in UPK.");
            // 根据你的逻辑，如果不存在可能需要提前返回 false，或者抛出异常
            // 这里为了保持最小改动，直接返回失败的计时结果
            return new SanitizingSubTimings(0, 0, false);
        }
        
        try {
            // >>>>> 纯链下计算计时 - 前置部分 <<<<<
            long computeStart = System.nanoTime();

            if (setup == null) {
                throw new IllegalStateException("Setup object is not initialized.");
            }
            // --- 纯链下计算部分结束，进入 Fabric 查询 ---
            currentOffChainComputeTime += (System.nanoTime() - computeStart);


            // >>>>> Fabric 链码查询计时开始 <<<<<
            long fabricQueryStart = System.nanoTime();
            Element phi_i = blockchain.getPhiByPublicKey(publicKey);
            long fabricQueryEnd = System.nanoTime();
            currentFabricQueryTime = (fabricQueryEnd - fabricQueryStart); // 记录 Fabric 查询时间
            // >>>>> Fabric 链码查询计时结束 <<<<<

            if (phi_i == null) {
                System.out.println("Phi_i not found for the provided public key.");
                return new SanitizingSubTimings(currentOffChainComputeTime, currentFabricQueryTime, false);
            }

            // >>>>> 纯链下计算计时 - 后置部分 <<<<<
            computeStart = System.nanoTime(); // 重新开始计时纯链下计算

            // 哈希计算，H0 和 H1
            Element H0 = setup.H0(data, signature.getV_i(), phi_i);
            Element H1 = setup.H1(data, signature.getV_i(), phi_i);

            boolean res = pairingCheck(
                signature,
                publicKey,
                H0,
                Y,
                P,
                H1
            );

            if (!res) {
                currentOffChainComputeTime +=
                        System.nanoTime() - computeStart;

                return new SanitizingSubTimings(
                        currentOffChainComputeTime,
                        currentFabricQueryTime,
                        false
                );
            }

            // in ADM 
            if(ADM.contains(signature.getId())){
                // 选择一个随机数 v'_i ∈ Zq*
                Element v_i_prime = setup.pairing.getZr().newRandomElement().getImmutable();
                // 计算 V'_i = v'_i * P
                Element V_i_prime = P.mulZn(v_i_prime).getImmutable();
                // 计算 m'_i = fmod(m_i) 和 t'_i = h(m'_i, ω_i, e(U_i, Y)^x)
                String m_i_prime = fmod(message.getM(),setup);  // fmod 操作
                String omega_i = message.getOmega();  // 获取 omega
                Element t_i_prime = setup.H(m_i_prime, omega_i, pairing.pairing(publicKey, Y).powZn(X));
                // 计算 Φ'_i = x * t'_i * Y
                Element phi_i_prime = Y.mulZn(t_i_prime).mulZn(X).getImmutable(); 
                
                Element update_HashValue0 = setup.H0(m_i_prime, V_i_prime, phi_i_prime);
                Element update_HashValue1 = setup.H1(m_i_prime, V_i_prime, phi_i_prime);

                Element T_i = update_HashValue0.mulZn(X).add(update_HashValue1.mulZn(v_i_prime));
                
                signature.setT_i(T_i );
                signature.setV_i(V_i_prime);
                signature.setPhi_i(phi_i_prime);
                message.setM(m_i_prime);
            }
            // --- 纯链下计算部分结束 ---
            currentOffChainComputeTime += (System.nanoTime() - computeStart);

            // 返回封装了细化时间的对象
            return new SanitizingSubTimings(currentOffChainComputeTime, currentFabricQueryTime, res);

        } catch (Exception e) {
            e.printStackTrace();
            return new SanitizingSubTimings(0, 0, false); // 发生异常时返回失败
        }
    }

    // 双线性映射验证
    private boolean pairingCheck(com.dvas.Sign.Signature signature, Element publicKey, Element H0, Element Y, Element P, Element H1) {
        Element leftSide = pairing.pairing(signature.getT_i(), P);
        Element rightSide = pairing.pairing(H0, publicKey).mul(pairing.pairing(H1, signature.getV_i()));
        return leftSide.isEqual(rightSide);
    }

    // fmod 算法：使用 SHA-256 哈希修改敏感数据 m_i（String 类型）
    public static String fmod(String m, Setup setup) {
        // 由于你的注释，这里不进行实际的哈希计算，直接返回 m
        // 如果你需要实际的哈希，请取消注释并确保相关导入
        return m;
    }
}