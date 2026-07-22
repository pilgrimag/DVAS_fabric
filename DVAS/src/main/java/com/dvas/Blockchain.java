package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.ContractException;

public class Blockchain {
    private Contract chaincodeContract;
    private Pairing pairing;
    private static final Gson GSON = new Gson();

    public Blockchain(Contract contract, Pairing pairingInstance) {
        this.chaincodeContract = contract;
        this.pairing = pairingInstance;
        // 初始确认信息，可以保留
        System.out.println("Blockchain adapter initialized. Now interacting with Fabric chaincode.");
    }

    // Auxiliary method: Element to Base64 String (public access)
    public String elementToBase64String(Element element) {
        if (element == null) return null;
        byte[] bytes = element.toBytes();
        String base64 = Base64.getEncoder().encodeToString(bytes);
        return base64;
    }

    // Auxiliary method: Base64 String to Element (public access)
    public Element base64StringToElement(String base64String) {
        if (base64String == null || base64String.isEmpty()) return null;
        byte[] bytes = Base64.getDecoder().decode(base64String);
        return pairing.getG1().newElementFromBytes(bytes).getImmutable();
    }

    // !!! 新增：提供一个公共方法用于 Main.java 直接提交单个映射 !!!
    public void addMapping(String publicKeyBase64, String phiBase64) throws Exception {
        // 这条打印信息现在由 Main.java 控制，或者你可以在 Main.java 中决定是否打印
        // System.out.println(String.format("Submitting addMapping to chaincode: PublicKey [%s]", publicKeyBase64));
        // try {
        //     // 执行链码事务提交
        //     System.out.println("beforesubmit");
        //     byte[] response = chaincodeContract.submitTransaction("addMapping", publicKeyBase64, phiBase64);
        //     System.out.println("aftersubmit");
        //     // 可以在这里打印链码响应，如果需要调试
        //     // System.out.println(String.format("addMapping response from chaincode: %s", new String(response, StandardCharsets.UTF_8)));
        // } catch (ContractException | InterruptedException | java.util.concurrent.TimeoutException e) {
        //     // 捕获可能发生的异常，并重新抛出，以便 Main.java 处理计时和错误报告
        //     System.err.println(String.format("Error submitting addMapping for PublicKey [%s]: %s", publicKeyBase64, e.getMessage()));
        //     throw e; // 重新抛出异常
        // }
        try {
            System.out.println("准备提交交易: addMapping");
            System.out.println("PublicKey: " + publicKeyBase64.substring(0, Math.min(50, publicKeyBase64.length())) + "...");
            
            byte[] response = chaincodeContract.submitTransaction("addMapping", publicKeyBase64, phiBase64);
            
            System.out.println("交易提交成功，响应: " + new String(response, StandardCharsets.UTF_8));
        } catch (ContractException e) {
            System.err.println("链码执行异常: " + e.getMessage());
            System.err.println("错误详情: " + e.getCause());
            throw e;
        } catch (InterruptedException e) {
            System.err.println("交易被中断: " + e.getMessage());
            throw e;
        } catch (java.util.concurrent.TimeoutException e) {
            System.err.println("交易超时: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.err.println("未知异常: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }


    // !!! 删除 addSensorMap 方法，因为它现在由 Main.java 接管其逻辑 !!!
    /*
    public void addSensorMap(Map<Element, Element> sensorMap) {
        if (sensorMap.isEmpty()) {
            System.out.println("No mappings to add to chaincode.");
            return;
        }

        for (Map.Entry<Element, Element> entry : sensorMap.entrySet()) {
            String publicKeyBase64 = elementToBase64String(entry.getKey());
            String phiBase64 = elementToBase64String(entry.getValue());

            try {
                // System.out.println(String.format("Submitting addMapping to chaincode: PublicKey [%s]", publicKeyBase64));
                byte[] response = chaincodeContract.submitTransaction("addMapping", publicKeyBase64, phiBase64);
            } catch (ContractException | InterruptedException | java.util.concurrent.TimeoutException e) {
                System.err.println(String.format("Error submitting addMapping for PublicKey [%s]: %s", publicKeyBase64, e.getMessage()));
                e.printStackTrace();
            }
        }
    }
    */

    public Element getPhiByPublicKey(Element publicKeyElement) throws Exception {
        String publicKeyBase64 = elementToBase64String(publicKeyElement);
        try {
            byte[] response = chaincodeContract.evaluateTransaction("queryPhi", publicKeyBase64);
            String phiBase64FromChaincode = new String(response, StandardCharsets.UTF_8);
            
            Element queriedPhi = base64StringToElement(phiBase64FromChaincode);
            return queriedPhi;
        } catch (ContractException e) {
            System.err.println(String.format("Error querying phi for PublicKey [%s]: %s", publicKeyBase64, e.getMessage()));
            e.printStackTrace();
            return null;
        }
    }

    public String getPhiBase64DirectlyFromChaincode(Element publicKeyElement) throws Exception {
        String targetPublicKeyBase64 = elementToBase64String(publicKeyElement);
        try {
            byte[] response = chaincodeContract.evaluateTransaction("queryAllMappings");
            String jsonResponse = new String(response, StandardCharsets.UTF_8);

            List<Map<String, String>> allMappings = GSON.fromJson(jsonResponse, new TypeToken<List<Map<String, String>>>(){}.getType());

            if (allMappings == null || allMappings.isEmpty()) {
                return null;
            }

            for (Map<String, String> mapping : allMappings) {
                String pkBase64 = mapping.get("publicKey");
                String phiBase64 = mapping.get("phi");
                
                if (pkBase64 != null && pkBase64.equals(targetPublicKeyBase64)) {
                    return phiBase64;
                }
            }
            return null;
        } catch (Exception e) {
            System.err.println("Error querying all mappings from chaincode: " + e.getMessage());
            throw e;
        }
    }

    public void printBlockchain() throws Exception {
        System.out.println("Querying all mappings from chaincode...");

        try {
            byte[] response = chaincodeContract.evaluateTransaction("queryAllMappings");
            String jsonResponse = new String(response, StandardCharsets.UTF_8);

            List<Map<String, String>> allMappings = GSON.fromJson(jsonResponse, new TypeToken<List<Map<String, String>>>(){}.getType());

            if (allMappings == null || allMappings.isEmpty()) {
                System.out.println("No mappings found on chaincode.");
                return;
            }

            int i = 1;
            for (Map<String, String> mapping : allMappings) {
                String pkBase64 = mapping.get("publicKey");
                String phiBase64 = mapping.get("phi");
                System.out.println(String.format("Mapping %d:\n  PublicKey: %s\n  Phi_i: %s", i++, pkBase64, phiBase64));
            }

        } catch (Exception e) {
            System.err.println("Error querying all mappings from chaincode: " + e.getMessage());
            throw e;
        }
    }
}