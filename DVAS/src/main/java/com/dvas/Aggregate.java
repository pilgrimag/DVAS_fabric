package com.dvas;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.dvas.Sign.Signature;
import com.dvas.sendToEN.Send;

public class Aggregate {
    private Setup setup;
    private Pairing pairing;
    private Field<Element> G1;
    private Field<Element> Zq;

    public Aggregate(Setup setup) {
        this.pairing = setup.pairing;
        this.G1 = setup.getG1();
        this.Zq = setup.getZp();
    }

    public AggregateResult computeAggregate(
        Setup setup,   
        Element P,
        Element Y,
        List<Signature> signatures,  // 接收签名列表
        int[] sensorIDs,
        List<Integer> ADM,
        List<Integer> FIX,
        Map<Element, Element> sensorMap,
        List<Send> Sends,
        List<Integer> Index
        

) {
    List<Element> VList = new ArrayList<>();
    List<Message> MM = new ArrayList<>();
    // 随机选择 z ∈ Zq*
    Field zrField = pairing.getZr();
    Element z = zrField.newRandomElement().getImmutable();

    // 计算 Z = zP
    Element Z = P.mulZn(z).getImmutable();

   // System.out.println("Agg Z value : " + Z);

    // 计算 Ψ = zY
    Element Psi = Y.mulZn(z).getImmutable();

    // 计算 ΣΦ_i'
    Element sumPhiPrime = G1.newZeroElement();

    for (Integer admSensorId : ADM) {  // 直接遍历ADM中的每个传感器ID
        for (Signature sig : signatures) {
            
            if (sig.getId() == admSensorId) {
                sumPhiPrime = sumPhiPrime.add(sig.getPhi_i());
             //   System.out.println("累加 Φ_" + admSensorId + ": " + sig.getPhi_i());
            }
        }
    }

    Map<Integer, Element> VMap = new HashMap<>();
    for (Signature sig : signatures) {
        int id = sig.getId();  
        VMap.put(id, sig.getV_i().getImmutable());
       // System.out.println("Agg id: " + id + " vmap: "+VMap);
    }


    // 计算 γ' = H2(Ψ + ΣΦ_i')
    Element hashInput = Psi.add(sumPhiPrime).getImmutable();
    Element gammaPrime = setup.H2_2(hashInput);

    //System.out.println("Agg 里的gamma: " + gammaPrime);
    //System.out.println("AggVerify 里的sumPhiPrime: " + sumPhiPrime);

    // 计算 ΣT_i
    Element sumT = G1.newZeroElement();
    for (com.dvas.Sign.Signature sig : signatures) {
        sumT = sumT.add(sig.getT_i());
    }
    sumT = sumT.getImmutable();

    Element FsumT = G1.newZeroElement();
    for(int i : FIX){
        FsumT = FsumT.add(signatures.get(i).getT_i());
    }
    //System.out.println("Agg FsumT: " + FsumT);

    Element AsumT = G1.newZeroElement();
    for(int i : ADM){
        AsumT = AsumT.add(signatures.get(i).getT_i());
    }

    FsumT = FsumT.getImmutable();
    AsumT = AsumT.getImmutable();
    sumT = sumT.getImmutable();

    // System.out.println("Agg AsumT: " + AsumT);

    // System.out.println("Agg F+A sumT: " + FsumT.add(AsumT));
     //System.out.println("Agg 里的sumT: " + sumT);

    Element right1 = pairing.getGT().newOneElement();
    Element right2 = pairing.getGT().newOneElement();
    Element left = pairing.getGT().newOneElement();
    Element right = pairing.getGT().newOneElement();
    Element res = pairing.getGT().newOneElement();


    right1 = right1.mul(pairing.pairing(FsumT,P));
    right2 = right2.mul(pairing.pairing(AsumT,P));
    left = left.mul(pairing.pairing(sumT,P));
    right = right1.mul(right2).getImmutable();

    //System.out.println("Agg i in FIx e(): " + right1);

    // if (left.isEqual(right))
    // {
    //     System.out.println("yeah! ");

    // }
    // else{
    //     System.out.println("TAT ");
    // }


    // 计算 T = γ' * ΣT_i
    Element T = sumT.mulZn(gammaPrime).getImmutable();
    //System.out.println("Agg T: " + T);
    res = pairing.pairing(T,P);
    //System.out.println("Agg Paringres: " + res);

    //Element Tleft = FsumT.mulZn(gammaPrime).getImmutable();

    for (Send s : Sends) {
        MM.add(s.getm_i());
    }

    // for (Message message : MM) {
    //     System.out.println("消息M: " + message.getM());
    //     System.out.println("omega: " + message.getOmega());
    // }


    // 返回聚合结果
    return new AggregateResult(
        T,
        VMap,
        Z,
        MM
    );
}


    // 内部类，用于存储聚合结果
    public static class AggregateResult {
        public Element T;
        Map<Integer, Element> VMap;
        public Element Z; 
        List<Message> M;
        

        public AggregateResult(Element T, Map<Integer, Element> VMap, Element Z, List<Message> M) {
            this.T = T;
            this.VMap=VMap;
            this.Z = Z;
            this.M = M;
        }

        public Element getZ() {
            return Z;
        }

        public Element getT() {
            return T;
        }

        public  Map<Integer, Element> getVMap(){
            return VMap;
        }

        public  List<Message> getM(){
            return M;
        }

        @Override
        public String toString() {
            return "AggregateResult { T = " + T + ", Z = " + Z + " }";
        }
    }
}
