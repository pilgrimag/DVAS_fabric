package com.dvas;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import com.dvas.Setup; 
import com.dvas.MC; 

public class Join {
    private Setup setup;
    
    // 存储已认证的传感器节点
    private List<Integer> certifiedNodes;
    // 存储敏感数据集合和非敏感数据集合
    private Set<String> sensitiveDataNodes;
    private Set<String> nonSensitiveDataNodes;
    
    // 存储敏感数据集合和非敏感数据集合
    public List<String> FIX;
    public List<String> ADM;
    
    public Join(Setup setup) {
        this.setup = setup;
        this.certifiedNodes = new LinkedList<>();
        this.sensitiveDataNodes = new HashSet<>();
        this.nonSensitiveDataNodes = new HashSet<>();
    }

    /**
     * 设备认证：处理感知节点的认证过程。
     * @param id_i 传感器节点标识
     * @param R_i 随机数
     * @return 认证结果，返回一个布尔值
     */
    public boolean authenticateSensor(int id_i, Element R_i, Element u_i) {
        // 计算 c_i = h'(ID_i, R_i)
        Element c_i = setup.hPrime(id_i, R_i);

        //Element[] UI = setup.getSystemParameters().getUI();
        
        // 计算 U_i = R_i + c_i * S
        //Element U_i = R_i.add(c_i.mul(setup.getS())).getImmutable();
        Element U_i = R_i.add(setup.getS().mulZn(c_i)).getImmutable();
        // 这里的验证通过逻辑应该依据具体的认证方案进行
        if (U_i.isEqual(u_i) && verifySensor(U_i)) {
            // 如果认证通过，将节点标记为已认证
            certifiedNodes.add(id_i);
            return true;
        }
        return false;
    }

    /**
     * 模拟验证感知节点：在实际应用中，可以替换为智能合约验证逻辑。
     * @param U_i 预期的公钥或验证值
     * @return 是否验证通过
     */
    private boolean verifySensor(Element U_i) {
        // 此处模拟验证过程
        // 你可以根据具体的认证方法实现验证逻辑
        return true;
    }

    /**
     * 任务分组：根据认证结果和数据敏感性分组。
     * @param id_i 传感器节点标识
     * @param isSensitive 数据是否敏感
     */
    public void groupTask(int id_i, boolean isSensitive, List<Integer> ADM,List<Integer> FIX) {
        // 将 id_i 从 String 转换为 Integer
        //Integer id = Integer.parseInt(id_i);
        if (certifiedNodes.contains(id_i)) {
            if (isSensitive) {
                try {
                    ADM.add(id_i);  // 将 Integer 类型的 id 添加到 ADM 列表
                } catch (NumberFormatException e) {
                    // 如果 id_i 不能转换为 Integer，处理异常
                    System.out.println("Invalid id_i format: " + id_i);
                }
            } else {
                FIX.add(id_i);  // 如果是非敏感数据，直接添加 id_i 到 FIX
            }
        }
    }

    /**
     * 授权与数据处理：在智能合约中达成授权协议并处理敏感数据。
     * @param id_i 传感器节点标识
     * @param isSensitive 是否为敏感数据
     */
    public void authorizeAndProcessData(int id_i, boolean isSensitive) {
        if (isSensitive && sensitiveDataNodes.contains(id_i)) {
            // 对敏感数据进行修改
            // 这里可以调用相应的数据修改函数，比如调用边缘节点（EN）来修改数据
            processSensitiveData(id_i);
        }
    }

    /**
     * 模拟处理敏感数据的函数
     * @param id_i 传感器节点标识
     */
    private void processSensitiveData(int id_i) {
        // 此处模拟数据处理过程
        // 在实际应用中，你可以通过智能合约或者协议修改敏感数据
        System.out.println("Processing sensitive data for node: " + id_i);
    }

    /**
     * 获取公钥集合 L_pk
     * @return 返回一个包含所有认证节点公钥的集合
     */
    public List<Element> getPublicKeySet() {
        List<Element> publicKeys = new LinkedList<>();
        for (int id_i : certifiedNodes) {
            SensorKeyPair keyPair = setup.getSensorKey(id_i);
            if (keyPair != null) {
                publicKeys.add(keyPair.getU_i());
            }
        }
        return publicKeys;
    }

    /**
     * 获取数据分组集合：包括敏感数据和非敏感数据的集合
     * @return 返回敏感数据和非敏感数据集合
     */
    public TaskGroups getTaskGroups() {
        return new TaskGroups(ADM, FIX);
    }

    /**
     * 存储敏感数据和非敏感数据的分组
     */
    public static class TaskGroups {
        private List<String> ADM;
        private List<String> FIX;

        public TaskGroups(List<String> sensitiveDataNodes, List<String> nonSensitiveDataNodes) {
            this.ADM = ADM;
            this.FIX = FIX;
        }

        public List<String> getSensitiveDataNodes() {
            return ADM;
        }

        public List<String> getNonSensitiveDataNodes() {
            return FIX;
        }
    }
}

