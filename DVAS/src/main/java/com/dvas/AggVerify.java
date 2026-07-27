package com.dvas;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import it.unisa.dia.gas.jpbc.Field;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dvas.Aggregate.AggregateResult;
import com.dvas.Setup;
import com.dvas.Sign.Signature;
import com.dvas.sendToEN.Send;

public class AggVerify {
    private Setup setup;
    private Pairing pairing;
    private Field<Element> G1;
    private Field<Element> GT;
    private Field<Element> Zq;

    public AggVerify(Setup setup) {
        this.pairing = setup.pairing;
        this.G1 = setup.getG1();
        this.GT = setup.getGT();
        this.Zq = setup.getZp();
    }

    public boolean verifyAggregate(
        Setup setup,
        Element T,             // 聚合签名的 T
        Element P,             // 系统参数 P
        Element X,             // EN的公钥
        Element y,             // DV的私钥 y
        Element Z,             // 聚合参数 Z
        List<Integer> FIX,     // FIX 集合的索引
        List<Integer> ADM,     // ADM 集合的索引
        List<Message> messages, // 消息列表，每个消息包含 m_i 和 ω_i
        Map<Integer, Element> UiMap,   // 公钥列表
        AggregateResult result,//里面有Vlist的顺序
        List<Element> PhiList,  // FIX 集合的 Phi_i 列表
        int n,                   //参与者的数量
        List<Integer> Index, 
        List<Element> UiList, 
        List<Element> VList,
        List<Send> sends

       
    ) {
        Map<Integer, Element> ti_Map = new HashMap<>();
        Map<Integer, Element> admMap0 = new HashMap<>();//对应admHash0
        Map<Integer, Element> admMap1 = new HashMap<>();//对应admHash1
        Map<Integer, Element> fixMap0 = new HashMap<>();//对应fixHash0
        Map<Integer, Element> fixMap1 = new HashMap<>();//对应fixHash1

        Element right1 = pairing.getGT().newOneElement();
        Element right2 = pairing.getGT().newOneElement();
        Element right = pairing.getGT().newOneElement();


        Map<Integer, Element> VMap =
                result.getVMap();

        //提前备好要用的东西
        Element sumPhiPrime = setup.pairing.getG1().newZeroElement();
        Element yZ = Z.mulZn(y).getImmutable(); 

        //System.out.println("AggVer Z value : " + Z);

        // 1- 计算 index 里的所有的 \hat{t_i} 数量:n
        for (int sensorId : ADM)//这个i对应的是id，我应该确认每个集合里的i是相关联的才行
         {
            String omegaElement = messages.get(sensorId).getOmega();
            Element tHat = setup.H(messages.get(sensorId).getM(), omegaElement, pairing.pairing(UiMap.get(sensorId), X).powZn(y));
            //System.out.println("AggVerify id: " + sensorId + "时的 Hat t_i: " + tHat);
            //System.out.println("tHat: " + tHat);
            //System.out.println("AggVerify id: " + sensorId + " U_i:" + UList.get(sensorId));
            //System.out.println("AggVerify id: " + sensorId +" e(U_i, X)^{y}: " + pairing.pairing(UList.get(sensorId), X).powZn(y));
            //System.out.println("AggVerify id: " + sensorId + "时的m_i: " + messages.get(sensorId).getM() + " omega_i:" + omegaElement);
            //System.out.println("AggVerify id: " + sensorId + "时的tHat: " + tHat );
            ti_Map.put(sensorId,tHat.getImmutable());

            // String output = "聚合时-传感器id为: " + sensorId;
            //     output += " 时，公钥 U_i为:" + UList.get(sensorId);
            // System.out.println(output);
        }
        //System.out.println("AggVer T: " + T);
       // System.out.println("AggVer Sends_T: " + );

        // 2- i \in FIX 的情况计算
        for (int i : FIX) {
            Element H0 = setup.H0(messages.get(i).getM(), VMap.get(i), PhiList.get(i));
            Element H1 = setup.H1(messages.get(i).getM(), VMap.get(i), PhiList.get(i));
            fixMap0.put(i, H0.getImmutable());
            fixMap1.put(i, H1.getImmutable());
        }

        // 3- i \in ADM 的情况计算
        for (int i : ADM) {
            // 获取 tHatList 中的元素
            Element tHat = ti_Map.get(i);
        
            // 计算 PhiHat
            Element PhiHat = X.mulZn(tHat.mul(y)).getImmutable();


            // System.out.println("AggVer id: " + i + " y*P: " + P.mulZn(y));
            // System.out.println(" X: " + X);

            //System.out.println("AggVer id: " + i + "时的PhiHat': " + PhiHat + " t_i: " + tHat);
    
            // 将 PhiHat 添加到 HatPhiList
    
            // 累加 PhiHat 到 sumPhiPrime
            sumPhiPrime = sumPhiPrime.add(PhiHat);
    
            // 计算 HashValue0 和 HashValue1
            
            Element HashValue0 = setup.H0(messages.get(i).getM(), VMap.get(i), PhiHat);
            
            //System.out.println("AggVer id: " + i + "时的message'': " +  messages.get(i).getM());
            // System.out.println("V_i: " + VList.get(i));
            // System.out.println("PhiHat: " + PhiHat);
            //System.out.println("AggVer id: " + i + "时的hatHashValue0': " +  HashValue0);
            Element HashValue1 = setup.H1(messages.get(i).getM(), VMap.get(i), PhiHat);
            //System.out.println("AggVer id: " + i + "时的HashValue1': " +  HashValue1);
            admMap0.put(i,HashValue0.getImmutable());
            admMap1.put(i,HashValue1.getImmutable());
        }
        // 4- 将 yZ 和累加后的 \sum \hat{\Phi}_i 相加
        Element gammaInput = yZ.add(sumPhiPrime);  // yZ + \sum \hat{\Phi}_i 
        // 计算系数 γ
        Element gamma = setup.H2_2(gammaInput).getImmutable();  // 使用 H2 函数计算 γ

        //System.out.println("AggVerify 里的gamma: " + gamma);

        //System.out.println("AggVerify 里的sumPhiPrime: " + sumPhiPrime);

        // 5- 验证等式
        Element left = pairing.pairing(T, P).getImmutable();
        //System.out.println("AggVerify 里的T: " + T);
         //System.out.println("AggVerify 里的result.getT(): " + result.getT());

//                 // 遍历 FIX 中的每个 i
//         for (int i : FIX) {
//     // 计算 e(H_{0_i}, γ U_i) 和 e(H_{1_i}, γ V_i)，并累乘到 right1
//             Element term1 = pairing.pairing(
//             fixMap0.get(i),          // H_{0_i}
//             UiMap.get(i).mulZn(gamma).getImmutable() // γ U_i
//             );
//             Element term2 = pairing.pairing(
//             fixMap1.get(i),          // H_{1_i}
//             VMap.get(i).mulZn(gamma).getImmutable()); // γ V_i

//             //System.out.println("AggVer i: "+ i + " fixMap1: "  + fixMap1.get(i));
//             //System.out.println("AggVer gamma : " + gamma);
//             //System.out.println("AggVer Ui : " + UiMap.get(i));
//             //System.out.println("AggVer EE i: "+ i + " U_i : " + UiMap.get(i));
//         //-----------------------分割线---------------------
    
//             right1 = right1.mul(term1);
//             right1 = right1.mul(term2);
//             right1 = right1.getImmutable();

// }
//         System.out.println("AggVer i in FIx e(): " + right1);

//         // 2.2. ADM 集合的验证
//         for (int i : ADM) {
//             Element Xgamma = X.mulZn(gamma).getImmutable();

//              right2 = right2.mul(pairing.pairing(admMap0.get(i), Xgamma))
//                          .mul(pairing.pairing(admMap1.get(i), VMap.get(i).mulZn(gamma))).getImmutable();
                         
//                         System.out.println("AggVer i: "+ i + " admMap0: "  + admMap0.get(i) + " admMap1: "  + admMap1.get(i));
//                         }
//          right = right1.mul(right2).getImmutable();

for (int i : FIX) {
    Element term1 = pairing.pairing(fixMap0.get(i), UiMap.get(i).powZn(gamma));
    Element term2 = pairing.pairing(fixMap1.get(i), VMap.get(i).powZn(gamma));
    //right1 = right1.mul(term1).mul(term2).getImmutable();
    right1 = right1.mul(term1);
    right1 = right1.mul(term2);
    right1 = right1.getImmutable();
}

for (int i : ADM) {
    Element Xgamma = X.powZn(gamma);
    Element Vgamma = VMap.get(i).powZn(gamma);
    Element term1 = pairing.pairing(admMap0.get(i), Xgamma);
    Element term2 = pairing.pairing(admMap1.get(i), Vgamma);
    right2 = right2.mul(term1);
    right2 = right2.mul(term2);
    right2 = right2.getImmutable();

    //System.out.println("AggVer ADM id: " + i + "时的hatHashValue0: " +  admMap0.get(i));
    //System.out.println("hatHashValue1: " +  admMap1.get(i));
    //System.out.println("V Value: " +  VMap.get(i));
}

//System.out.println("AggVer X: " + X );
    right = right1.duplicate().mul(right2).getImmutable();

//System.out.println("left = " + left);
//System.out.println("right1 = " + right1);
//System.out.println("right2 = " + right2);
//System.out.println("final right = " + right);
//System.out.println("equal? " + left.isEqual(right));

//System.out.println("AggVer gamma : " + gamma);

         

        // 比较左侧和右侧
        return left.isEqual(right);
    }

}
