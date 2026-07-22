package com.dvas.chaincode;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ResponseUtils;

public class DVASChaincode extends ChaincodeBase {

    private static Pairing pairing;
    private static final Gson GSON = new Gson();

    static {
        // !!! 关键：这里的 JPBC Pairing 初始化方式必须与您的客户端 Setup.java 中的参数和配置完全一致 !!!
        // 否则 Element 的 toBytes() 结果可能不一致
        TypeACurveGenerator pg = new TypeACurveGenerator(160, 512); // 请确保这里的参数 (160, 512) 与 Setup.java 完全一致
        PairingParameters typeAParams = pg.generate();
        pairing = PairingFactory.getPairing(typeAParams);
        PairingFactory.getInstance().setUsePBCWhenPossible(true); // 请确保这个设置也与 Setup.java 完全一致
        //System.out.println("Chaincode: JPBC Pairing initialized.");
    }

    // 辅助方法：Element 到 Base64 字符串
    // 尽管我们会在链码中避免不必要的 Element 转换，但保留此方法以供需要时使用
    private String elementToBase64String(Element element) {
        if (element == null) return null;
        byte[] bytes = element.toBytes();
        String base64 = Base64.getEncoder().encodeToString(bytes);
        //System.out.println(String.format("Chaincode DEBUG (Element->Base64): Element Type: %s, ToBytes Length: %d, Base64 Length: %d, Value: %s", element.getClass().getSimpleName(), bytes.length, base64.length(), base64));
        return base64;
    }

    // 辅助方法：Base64 字符串到 Element
    // 只有在链码内部确实需要对 Element 进行密码学操作时才使用此方法。
    // 否则，为了避免转换问题，最好直接操作 Base64 字符串。
    // 根据之前的分析，PublicKey 和 Phi_i 都属于 G1 群。
    private Element base64StringToElement(String base64String) {
        if (base64String == null || base64String.isEmpty()) return null;
        byte[] bytes = Base64.getDecoder().decode(base64String);
        //System.out.println(String.format("Chaincode DEBUG (Base64->Element): Base64 Length: %d, Decoded Bytes Length: %d, Value: %s", base64String.length(), bytes.length, base64String));
        // 这里必须调用与元素实际群类型匹配的方法
        return pairing.getG1().newElementFromBytes(bytes).getImmutable();
    }

    // ---------------------------- ChaincodeBase 核心方法 ----------------------------

    @Override
    public Response init(ChaincodeStub stub) {
        //System.out.println("DVAS Chaincode Init completed.");
        return ResponseUtils.newSuccessResponse("Init Success!");
    }

    @Override
    public Response invoke(ChaincodeStub stub) {
        String func = stub.getFunction();
        List<String> args = stub.getParameters();

        //System.out.println(String.format("Chaincode: Invoke function: %s, args: %s", func, args));

        try {
            switch (func) {
                case "InitLedger":
                    return ResponseUtils.newSuccessResponse("InitLedger function called.");

                case "addMapping":
                    if (args.size() != 2) {
                        return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 2 for addMapping: [publicKeyBase64, phiBase64].");
                    }
                    String addResult = addMapping(stub, args.get(0), args.get(1));
                    return ResponseUtils.newSuccessResponse(addResult);

                case "queryPhi":
                    if (args.size() != 1) {
                        return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 1 for queryPhi: [publicKeyBase64].");
                    }
                    String phiResult = queryPhi(stub, args.get(0)); // queryPhi 现在直接返回 Base64 字符串
                    if (phiResult == null) {
                        return ResponseUtils.newErrorResponse(String.format("Phi_i not found for PublicKey [%s]", args.get(0)));
                    }
                    return ResponseUtils.newSuccessResponse(phiResult.getBytes(StandardCharsets.UTF_8));

                case "queryAllMappings":
                    if (!args.isEmpty()) {
                        return ResponseUtils.newErrorResponse("No arguments expected for queryAllMappings.");
                    }
                    String allMappingsResult = queryAllMappings(stub);
                    return ResponseUtils.newSuccessResponse(allMappingsResult.getBytes(StandardCharsets.UTF_8));

                default:
                    return ResponseUtils.newErrorResponse("Invalid chaincode function name: " + func);
            }
        } catch (Throwable e) {
            System.err.println("Chaincode ERROR: Error invoking function " + func + ": " + e.getMessage());
            e.printStackTrace();
            return ResponseUtils.newErrorResponse("Error during chaincode invocation: " + e.getMessage());
        }
    }

    // ---------------------------- 您的业务逻辑方法 ----------------------------

    public String addMapping(ChaincodeStub stub, String publicKeyBase64, String phiBase64) {
        if (publicKeyBase64 == null || publicKeyBase64.isEmpty() || phiBase64 == null || phiBase64.isEmpty()) {
            throw new RuntimeException("Public key and phi_i cannot be empty");
        }

        // 链码接收到的 Base64 字符串长度
        //System.out.println(String.format("Chaincode DEBUG (addMapping): Received PublicKey Base64 length: %d", publicKeyBase64.length()));
        //System.out.println(String.format("Chaincode DEBUG (addMapping): Received Phi_i Base64 length: %d", phiBase64.length()));

        // 将 Base64 字符串直接存储为字节数组，这是最稳定的方式
        byte[] phiBytesToStore = phiBase64.getBytes(StandardCharsets.UTF_8);
        //System.out.println(String.format("Chaincode DEBUG (addMapping): Storing Phi_i as bytes. Bytes length: %d", phiBytesToStore.length));

        stub.putState(publicKeyBase64, phiBytesToStore);

        //System.out.println(String.format("Chaincode DEBUG: Mapping added to ledger. PublicKey [%s] -> Phi_i (Base64) [%s]", publicKeyBase64, phiBase64));
        return "Mapping added successfully.";
    }

    public String queryPhi(ChaincodeStub stub, String publicKeyBase64) {
        if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            throw new RuntimeException("Public key cannot be empty");
        }

        byte[] phiBytesFromLedger = stub.getState(publicKeyBase64);

        if (phiBytesFromLedger == null || phiBytesFromLedger.length == 0) {
            //System.out.println(String.format("Chaincode DEBUG (queryPhi): Phi_i not found for PublicKey [%s]", publicKeyBase64));
            return null;
        }

        String phiBase64FromLedger = new String(phiBytesFromLedger, StandardCharsets.UTF_8);
        //System.out.println(String.format("Chaincode DEBUG (queryPhi): Retrieved Phi_i Base64 from ledger: [%s]", phiBase64FromLedger));

        // 关键修正：queryPhi 方法现在直接返回从账本读取的原始 Base64 字符串
        // 不再进行 Element 的来回转换，因为这可能导致数据不匹配
        return phiBase64FromLedger;
    }

    public String queryAllMappings(ChaincodeStub stub) {
        List<Map<String, String>> allMappings = new ArrayList<>();
        stub.getStateByRange("", "").forEach(kv -> {
            Map<String, String> mapping = new HashMap<>();
            String publicKeyBase64 = kv.getKey();
            String phiBase64 = new String(kv.getValue(), StandardCharsets.UTF_8);

            mapping.put("publicKey", publicKeyBase64); // 直接使用 Base64 字符串
            mapping.put("phi", phiBase64); // 直接使用 Base64 字符串
            allMappings.add(mapping);

            //System.out.println(String.format("Chaincode DEBUG (queryAllMappings): Read PK Base64 length: %d, Phi Base64 length: %d", publicKeyBase64.length(), phiBase64.length()));
            //System.out.println(String.format("Chaincode DEBUG (queryAllMappings): Read PK: [%s], Phi: [%s]", publicKeyBase64, phiBase64));
        });

        String jsonResult = GSON.toJson(allMappings);
        //System.out.println("Chaincode DEBUG: queryAllMappings returning JSON: " + jsonResult);
        return jsonResult;
    }

    // ---------------------------- Main 方法 (用于本地运行和调试) ----------------------------
    /**
     * Main 方法用于在本地测试或作为链码入口点启动。
     * 当链码部署到 Fabric 网络时，Fabric peer 会调用这个 main 方法来启动链码。
     */
    public static void main(String[] args) {
        //System.out.println("Starting DVASChaincode...");
        // 调用 ChaincodeBase 的 start 方法来启动链码监听器
        new DVASChaincode().start(args);
    }
}