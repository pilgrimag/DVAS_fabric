package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import it.unisa.dia.gas.jpbc.Field;


/**
 * Setup 类负责初始化配对、生成密钥以及分发密钥。
 */
public class Setup {
    // 配对对象
    public Pairing pairing;
    private Field<Element> G1, G2, GT, Zp;

    // 群 G1 和 G2 的生成元
    private Element P; // G1 的生成元
    private Element Q; // G2 的生成元

    // 主控制器 (MC) 的私钥和公钥
    private Element s; // 私钥
    public Element S; // 公钥，S = sP

    // 其他实体的公私钥
    public Element X; // 边缘节点 (EN) 的公钥
    public Element Y; // 数据验证节点 (DV) 的公钥
    public Element x; // 边缘节点 (EN) 的私钥
    public Element y; // 数据验证节点 (DV) 的私钥
    public Element U_i; 

    // 存储传感器节点 (SN_i) 的密钥对
    private Map<Integer, SensorKeyPair> sensorKeys;

    // 存储边缘节点 (EN) 和数据验证节点 (DV) 的密钥对
    private Map<Integer, SensorKeyPair> edgeNodeKeys;
    private Map<Integer, SensorKeyPair> dvNodeKeys;
    
    public Element[] UI;

    public Element getS() {
        return S;
    }
    public Element getP() {
        return P;
    }
    // 获取 Pairing 对象
    public Pairing getPairing() {
        return pairing;
    }
    
    public Field<Element> getG1() {
        return G1;
    }
    public void setG1(Field<Element> G1) {
        this.G1 = G1;  
    }
    public Field<Element> getGT() {
        return GT;
    }
    public void setGT(Field<Element> GT) {
        this.GT = GT;  
    }
    public Field<Element> getZp() {
        return Zp;
    }
    public void setZp(Field<Element> Zp) {
        this.Zp = Zp;  
    }

    

    
    public SystemParameters systemParameters;
    /**
     * 构造函数，初始化配对和密钥。
     */
    public Setup() {
        // 初始化 Pairing 参数，指定参数文件的路径
        //pairing = PairingFactory.getPairing("params/a.properties");
        TypeACurveGenerator pg = new TypeACurveGenerator(160, 512);
        PairingParameters typeAParams = pg.generate();
        Pairing pairing = PairingFactory.getPairing(typeAParams);
        
        // 设置是否使用 PBC 库的优化
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        G1 = pairing.getG1();
        G2 = pairing.getG2();
        Zp = pairing.getZr();
        
        // 生成 G1 和 G2 的生成元 P 和 Q
        P = G1.newRandomElement().getImmutable();
        Q = pairing.getG2().newRandomElement().getImmutable();
        
        // 主控制器 (MC) 的密钥生成
        s = pairing.getZr().newRandomElement().getImmutable(); // 随机选择 s ∈ Zq*
        S = P.mulZn(s).getImmutable(); // S = sP
        //MC mc = new MC(pairing,P);
        
        // 其他实体的密钥生成
        x = pairing.getZr().newRandomElement().getImmutable(); 
        y = pairing.getZr().newRandomElement().getImmutable();
        X = P.mulZn(x).getImmutable(); // EN 的公钥
        Y = P.mulZn(y).getImmutable(); // DV 的公钥
        
        // 初始化传感器节点密钥存储
        sensorKeys = new HashMap<>();
        edgeNodeKeys = new HashMap<>();
        dvNodeKeys = new HashMap<>();

        // 初始化 UI 数组
        Element[] UI = new Element[10000]; // 假设 UI 数组长度为 10
        systemParameters = new SystemParameters(pairing, P, Q, X, Y, UI);
        this.pairing = pairing;

    }

    /**
     * Hash h: 接受单一输入，将 {0,1} × G2 映射到 Zq。
     * @param inputs 输入对象数组，其中 inputs[0] 应该是 Byte，inputs[1] 应该是 Element
     * @return 映射后的 Zq 元素
     */
    public Element h(Object... inputs) {
        if (inputs.length != 2) {
            throw new IllegalArgumentException("h requires exactly 2 inputs: Byte and Element");
        }
        byte bit;
        Element g2Element;
        try {
            bit = (Byte) inputs[0];
            g2Element = (Element) inputs[1];
        } catch (ClassCastException e) {
            throw new IllegalArgumentException("h inputs must be of type Byte and Element", e);
        }
        byte[] bitBytes = new byte[] { bit };
        byte[] g2Bytes = g2Element.toBytes();
        byte[] combined = concatenate(bitBytes, g2Bytes);
        Element hash = pairing.getZr().newElement();
        hash.setFromHash(combined, 0, combined.length).getImmutable();
        return hash;
    }

    /**
     * Hash h': 接受两个输入，将 {ID_i, R_i} 映射到 Zq。
     * @param inputs 输入对象数组，其中 inputs[0] 应该是 int，inputs[1] 应该是 Element
     * @return 映射后的 Zq 元素
     */
    public Element hPrime(Object... inputs) {
        if (inputs.length != 2) {
            throw new IllegalArgumentException("hPrime requires exactly 2 inputs: String and Element");
        }
        int id_i;
        Element R_i;
        try {
            id_i = (int) inputs[0];
            R_i = (Element) inputs[1];
        } catch (ClassCastException e) {
            throw new IllegalArgumentException("hPrime inputs must be of type int and Element", e);
        }
        byte[] idBytes = ByteBuffer.allocate(4).putInt(id_i).array();
        byte[] R_iBytes = R_i.toBytes();
        byte[] combined = concatenate(idBytes, R_iBytes);
        Element hash = pairing.getZr().newElement();
        hash.setFromHash(combined, 0, combined.length).getImmutable();
        return hash;
    }
    public Element H(String m, String V, Element Phi) {
        // 将多个输入连接成一个字节数组
        byte[] input = concatenate(m.getBytes(), V.getBytes(), Phi.toBytes());
        // 通过哈希值映射到 Zq
        byte[] hash = sha256(input);
        Element hashElement = pairing.getZr().newElementFromHash(hash, 0, hash.length); // 将字节数组映射到 Zq
        return hashElement;
    }

    // H0 和 H1 采用相同的处理方式
    public Element H0(String m, Element V, Element Phi) {
        // 将多个输入连接成一个字节数组
        byte[] input = concatenate(m.getBytes(), V.toBytes(), Phi.toBytes());
        // 通过哈希值映射到 G1
        byte[] hash = sha256(input);
        Element hashElement = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        return hashElement.getImmutable(); // 将连接后的字节数组映射到 G1
    }

    // public Element H1(String m, Element V, Element Phi) {
    //      // 将多个输入连接成一个字节数组
    //      byte[] input = concatenate(m.getBytes(), V.toBytes(), Phi.toBytes());
    //      // 通过哈希值映射到 G1
    //      byte[] hash = sha256(input);
    //      Element hashElement = pairing.getG1().newElementFromHash(hash, 0, hash.length);
    //      return hashElement.getImmutable(); // 将连接后的字节数组映射到 G1
    // }
    public Element H1(String m, Element V, Element Phi) {
        byte[] prefix = new byte[]{0x01};  
        byte[] input = concatenate(prefix, m.getBytes(), V.toBytes(), Phi.toBytes());
        byte[] hash = sha256(input);
        Element hashElement = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        return hashElement.getImmutable();
    }
    

     // 连接多个字节数组
     private byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];
        int currentPos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentPos, array.length);
            currentPos += array.length;
        }
        return result;
    }

    // H_2 哈希函数：从 G1 映射到 {0, 1}*
    public String H2(Element g1Element) {
        // 将 G1 群元素转换为字节数组
        byte[] elementBytes = g1Element.toBytes();
        
        // 使用 SHA-256 哈希函数进行散列
        byte[] hash = sha256(elementBytes);
        
        // 将哈希值转换回字符串（可以根据需要进行编码转换）
        return bytesToHex(hash);
    }

        // H_2 哈希函数：从 G1 映射到 Zr
    
        public Element H2_2(Element g1Element) {
    // 转换为字节
    byte[] input =  g1Element.toBytes();
    // 通过哈希值映射到 Zq
    byte[] hash = sha256(input);
    Element hashElement = pairing.getZr().newElementFromHash(hash, 0, hash.length); // 将字节数组映射到 Zq
    return hashElement.getImmutable();
}


    // 将字节数组转换为十六进制字符串
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // SHA-256 哈希函数
    private byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * 分发密钥给传感器节点 (SN_i)。
     * @param id_i 传感器节点的身份标识
     * @return 传感器节点的密钥对 (R_i, u_i)
     */
    public SensorKeyPair distributeKeyToSensor(int id_i) {
        // 随机选择 r_i ∈ Zq*
        Element r_i = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 R_i = r_i P
        Element R_i = P.mulZn(r_i).getImmutable();
        
        // 计算 h'(ID_i, R_i)
        Element hPrimeValue = hPrime(id_i, R_i);
        
        // 计算 u_i = r_i + s h'(ID_i, R_i) mod q
        Element u_i = r_i.add(s.mulZn(hPrimeValue)).getImmutable();
        //Element u_i = (S.mulZn(hPrimeValue)).add(R_i).getImmutable();
        Element U_i = P.duplicate().mulZn(u_i).getImmutable(); 

          // 获取 UI 数组
          Element[] UI = systemParameters.getUI();
        
          // 检查当前索引是否有效，如果有效则存储 u_i
          int index = systemParameters.getCurrentIndex();
          if (index < UI.length) {
              UI[index] = u_i; // 存储到 UI[index]
              systemParameters.incrementIndex(); // 更新存储索引
          } else {
              // 如果索引超出范围，可以选择重置或抛出异常
              System.out.println("UI array is full.");
          }
          
          // 更新 SystemParameters 中的 UI 数组
          systemParameters.setUI(UI);
        
        // 存储密钥对
        SensorKeyPair keyPair = new SensorKeyPair(R_i, u_i, U_i, id_i);
        sensorKeys.put(id_i, keyPair);
        
        return keyPair;
    }

     /**
     * 获取所有传感器节点的密钥对
     * @return 所有传感器节点的密钥对集合
     */
    public Map<Integer, SensorKeyPair> getAllSensorKeys() {
        return sensorKeys;
    }
    
    /**
     * 根据传感器节点 ID 获取其密钥对
     * @param id_i 传感器节点的身份标识
     * @return 对应传感器节点的密钥对
     */
    public SensorKeyPair getSensorKey(int id_i) {
        return sensorKeys.get(id_i);
    }

    /**
     * 分发密钥给边缘节点 (EN)。
     * @param enID 边缘节点的身份标识
     * @return 边缘节点的密钥对 (R_i, u_i)
     */
    public SensorKeyPair distributeKeyToEdgeNode(int enID) {
        // 随机选择 r_i ∈ Zq*

        Element r_i = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 R_i = r_i P
        Element R_i = P.mulZn(r_i).getImmutable();
        
        // 计算 h'(EN_ID, R_i)
        Element hPrimeValue = hPrime(enID, R_i);
        
        // 计算 u_i = r_i + s h'(EN_ID, R_i) mod q
        Element u_i = r_i.add(s.mul(hPrimeValue)).getImmutable();

        Element U_i = P.duplicate().mulZn(u_i).getImmutable(); 

        // 存储密钥对
        SensorKeyPair keyPair = new SensorKeyPair(R_i, u_i, U_i, enID);
        edgeNodeKeys.put(enID, keyPair);
        
        return keyPair;
    }

    /**
     * 分发密钥给数据验证节点 (DV)。
     * @param dvID 数据验证节点的身份标识
     * @return 数据验证节点的密钥对 (R_i, u_i)
     */
    public SensorKeyPair distributeKeyToDVNode(int dvID) {
        // 随机选择 r_i ∈ Zq*
        Element r_i = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 R_i = r_i P
        Element R_i = P.mulZn(r_i).getImmutable();
        
        // 计算 h'(DV_ID, R_i)
        Element hPrimeValue = hPrime(dvID, R_i);
        
        // 计算 u_i = r_i + s h'(DV_ID, R_i) mod q
        Element u_i = r_i.add(s.mul(hPrimeValue)).getImmutable();
        
        Element U_i = P.duplicate().mulZn(u_i).getImmutable(); 

        // 存储密钥对
        SensorKeyPair keyPair = new SensorKeyPair(R_i, u_i, U_i, dvID);
        dvNodeKeys.put(dvID, keyPair);
        
        return keyPair;
    }

    /**
     * 验证传感器节点 (SN_i) 的密钥。
     * @param id_i 传感器节点的身份标识
     * @param keyPair 传感器节点的密钥对 (R_i, u_i)
     * @return 验证结果，true 表示验证通过，false 表示验证失败
     */
    public boolean verifySensorKey(int id_i, SensorKeyPair keyPair) {
        // 计算 U_i = u_i P
        Element U_i = P.duplicate().mulZn(keyPair.getu_i()).getImmutable(); 
        
        // 计算 R_i + h'(ID_i, R_i) S
        Element expectedU_i = keyPair.getR_i().add(S.duplicate().mulZn(hPrime(id_i, keyPair.getR_i())));
        
        // 检查 U_i 是否等于 expectedU_i
        return U_i.isEqual(expectedU_i);
    }

    /**
     * 获取系统参数 pp。
     * @return 系统参数对象
     */
    public SystemParameters getSystemParameters() {
    return systemParameters;
    }

    /**
     * 辅助方法：拼接两个字节数组。
     * @param a 第一个字节数组
     * @param b 第二个字节数组
     * @return 拼接后的字节数组
     */
    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }

    /**
     * SystemParameters 类用于存储系统的公开参数。
     */
    public static class SystemParameters {
        private Pairing pairing;
        private Element P;
        private Element Q;
        private Element X;
        private Element Y;
        private Element[] UI;
        private int currentIndex; // 当前存储的位置索引
        
        public SystemParameters(Pairing pairing, Element P, Element Q, Element X, Element Y, Element[] UI) {
            this.pairing = pairing;
            this.P = P;
            this.Q = Q;
            this.X = X;
            this.Y = Y;
            this.UI = UI;
        }

        // Getter 方法
        public Pairing getPairing() {
            return pairing;
        }

        public Element getP() {
            return P;
        }

        public Element getQ() {
            return Q;
        }

        public Element getX() {
            return X;
        }

        public Element getY() {
            return Y;
        }

        public Element[] getUI() {
            return UI;
        }

          // 获取当前存储索引
    public int getCurrentIndex() {
        return currentIndex;
    }

    // 更新 UI 数组
    public void setUI(Element[] UI) {
        this.UI = UI;
    }

    // 更新存储位置索引
    public void incrementIndex() {
        if (currentIndex < UI.length) {
            currentIndex++;
        } else {
            // 如果索引超出范围，可以选择重置或抛出异常
            throw new IndexOutOfBoundsException("UI array is full.");
        }
    }
    }

    /**
     * HashFunction 接口，用于定义哈希函数的行为。
     */
    public interface HashFunction {
        Element hash(Object... inputs);
    }

     
}
