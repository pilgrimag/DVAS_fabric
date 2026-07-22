// package com.dvas.chaincode;

// import it.unisa.dia.gas.jpbc.Element;
// import it.unisa.dia.gas.jpbc.Field; // 添加此导入
// import it.unisa.dia.gas.jpbc.Pairing;
// import it.unisa.dia.gas.jpbc.PairingParameters; // 添加此导入
// import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
// import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

// import java.security.MessageDigest; // 添加此导入
// import java.security.NoSuchAlgorithmException; // 添加此导入
// import java.util.Base64; // 添加此导入
// import java.util.ArrayList; // 添加此导入
// import java.util.HashMap; // 添加此导入
// import java.util.List;
// import java.util.Map;
// import java.nio.charset.StandardCharsets; // 添加此导入

// import com.google.gson.Gson;
// import com.google.gson.reflect.TypeToken; // 添加此导入

// import org.hyperledger.fabric.shim.ChaincodeBase;
// import org.hyperledger.fabric.shim.ChaincodeStub;
// import org.hyperledger.fabric.shim.ResponseUtils;

// public class DVASChaincode extends ChaincodeBase { // 继承 ChaincodeBase

//     private static Pairing pairing;
//     private static final Gson GSON = new Gson(); // 实例化 Gson

//     static {
//         // !!! 与您的 Setup.java 保持完全一致的 JPBC Pairing 初始化方式 !!!
//         TypeACurveGenerator pg = new TypeACurveGenerator(160, 512); // 使用 Setup 中的参数
//         PairingParameters typeAParams = pg.generate();
//         pairing = PairingFactory.getPairing(typeAParams);
//         PairingFactory.getInstance().setUsePBCWhenPossible(true); // 与 Setup.java 相同
//     }

//     // 辅助方法：Element 到 Base64 字符串
//     private String elementToBase64String(Element element) {
//         if (element == null) return null;
//         return Base64.getEncoder().encodeToString(element.toBytes());
//     }

//     // 辅助方法：Base64 字符串到 Element (假设 PublicKey 和 Phi_i 都在 G1 群)
//     private Element base64StringToElement(String base64String) {
//         if (base64String == null || base64String.isEmpty()) return null;
//         byte[] bytes = Base64.getDecoder().decode(base64String);
//         return pairing.getG1().newElementFromBytes(bytes).getImmutable(); // 确认为 G1
//     }

//     // ---------------------------- ChaincodeBase 核心方法 ----------------------------

//     /**
//      * 实现 ChaincodeBase 的 init 方法。
//      * 链码实例化或升级时调用。
//      */
//     @Override
//     public Response init(ChaincodeStub stub) {
//         System.out.println("DVAS Chaincode Init completed.");
//         // 如果 InitLedger 有任何实际的初始化逻辑，可以移到这里。
//         // 由于你的 InitLedger 只是打印，这里也只是打印。
//         return ResponseUtils.newSuccessResponse("Init Success!");
//     }

//     /**
//      * 实现 ChaincodeBase 的 invoke 方法。
//      * 所有链码调用都会进入这里。
//      */
//     @Override
//     public Response invoke(ChaincodeStub stub) {
//         String func = stub.getFunction(); // 获取调用的函数名
//         List<String> args = stub.getParameters(); // 获取参数列表

//         System.out.println(String.format("Invoke function: %s, args: %s", func, args));

//         try {
//             switch (func) {
//                 case "InitLedger": // 保留 InitLedger 作为可调用的函数，虽然通常只在部署时调用 init
//                     // 实际的初始化逻辑由 init(stub) 方法处理，这里只是响应客户端调用
//                     return ResponseUtils.newSuccessResponse("InitLedger function called.");

//                 case "addMapping":
//                     if (args.size() != 2) {
//                         return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 2 for addMapping: [publicKeyBase64, phiBase64].");
//                     }
//                     String addResult = addMapping(stub, args.get(0), args.get(1));
//                     return ResponseUtils.newSuccessResponse(addResult);

//                 case "queryPhi":
//                     if (args.size() != 1) {
//                         return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 1 for queryPhi: [publicKeyBase64].");
//                     }
//                     String phiResult = queryPhi(stub, args.get(0));
//                     // queryPhi 可能会返回 null，需要处理
//                     if (phiResult == null) {
//                         return ResponseUtils.newErrorResponse(String.format("Phi_i not found for PublicKey [%s]", args.get(0)));
//                     }
//                     return ResponseUtils.newSuccessResponse(phiResult.getBytes(StandardCharsets.UTF_8)); // 查询结果通常以字节数组返回

//                 case "queryAllMappings":
//                     if (!args.isEmpty()) { // queryAllMappings 不接受参数
//                         return ResponseUtils.newErrorResponse("No arguments expected for queryAllMappings.");
//                     }
//                     String allMappingsResult = queryAllMappings(stub);
//                     return ResponseUtils.newSuccessResponse(allMappingsResult.getBytes(StandardCharsets.UTF_8));

//                 // 如果 addSensorMapBatch 启用，也需要类似处理
//                 // case "addSensorMapBatch":
//                 //     if (args.size() != 1) {
//                 //         return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 1 for addSensorMapBatch: [jsonMappings].");
//                 //     }
//                 //     String batchResult = addSensorMapBatch(stub, args.get(0));
//                 //     return ResponseUtils.newSuccessResponse(batchResult);

//                 default:
//                     // 未知函数调用
//                     return ResponseUtils.newErrorResponse("Invalid chaincode function name: " + func);
//             }
//         } catch (Throwable e) {
//             // 捕获业务逻辑中可能抛出的任何异常，并返回错误响应
//             System.err.println("Error invoking function " + func + ": " + e.getMessage());
//             e.printStackTrace();
//             return ResponseUtils.newErrorResponse("Error during chaincode invocation: " + e.getMessage());
//         }
//     }

//     // ---------------------------- 您的业务逻辑方法 ----------------------------

//     /**
//      * 替换 Blockchain.addSensorMap() 中的单个 publicKey -> phi_i 映射。
//      * 由于 Blockchain.java 中的 getPhiByPublicKey 是全局遍历的，所以我们将 PublicKey 作为账本的键。
//      *
//      * @param stub              链码 stub
//      * @param publicKeyBase64  Base64 编码的 PublicKey Element
//      * @param phiBase64        Base64 编码的 Phi_i Element
//      * @return 成功消息
//      */
//     public String addMapping(ChaincodeStub stub, String publicKeyBase64, String phiBase64) {
//         if (publicKeyBase64 == null || publicKeyBase64.isEmpty() || phiBase64 == null || phiBase64.isEmpty()) {
//             throw new RuntimeException("Public key and phi_i cannot be empty");
//         }

//         // ***** 修正这里：直接存储 Base64 字符串的字节表示 *****
//         stub.putState(publicKeyBase64, phiBase64.getBytes(StandardCharsets.UTF_8));

//         System.out.println(String.format("Mapping added: PublicKey [%s] -> Phi_i [%s]", publicKeyBase64, phiBase64));
//         return "Mapping added successfully.";
//     }

//     /**
//      * 替换 Blockchain.getPhiByPublicKey()。
//      * 根据公钥查询对应的 phi_i。
//      *
//      * @param stub              链码 stub
//      * @param publicKeyBase64  Base64 编码的 PublicKey Element
//      * @return Base64 编码的 Phi_i Element，如果未找到则返回 null。
//      */
//     public String queryPhi(ChaincodeStub stub, String publicKeyBase64) {
//         if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
//             throw new RuntimeException("Public key cannot be empty");
//         }

//         byte[] phiBytesFromLedger = stub.getState(publicKeyBase64); // 获取的是 Base64 字符串的字节表示

//         if (phiBytesFromLedger == null || phiBytesFromLedger.length == 0) {
//             System.out.println(String.format("Phi_i not found for PublicKey [%s]", publicKeyBase64));
//             return null; // 返回 null 表示未找到
//         }

//         // ***** 修正这里：先将字节数组转回 Base64 字符串，再转为 Element *****
//         String phiBase64FromLedger = new String(phiBytesFromLedger, StandardCharsets.UTF_8);
//         Element phi = base64StringToElement(phiBase64FromLedger); // 将 Base64 字符串转回 Element

//         System.out.println(String.format("Phi_i found: PublicKey [%s] -> Phi_i [%s]", publicKeyBase64, elementToBase64String(phi)));
//         return elementToBase64String(phi);
//     }

//     /**
//      * 替换 Blockchain.getAllSensorMaps() / printBlockchain() 的部分功能。
//      * 返回所有存储的 (PublicKey, Phi_i) 映射。
//      * 注意：对于大量数据，这可能效率低下。
//      * @param stub 链码 stub
//      * @return 包含所有映射的 JSON 字符串。
//      */
//     public String queryAllMappings(ChaincodeStub stub) {
//         List<Map<String, String>> allMappings = new ArrayList<>();

//         stub.getStateByRange("", "").forEach(kv -> {
//             Map<String, String> mapping = new HashMap<>();
            
//             // kv.getKey() 本身就是 publicKeyBase64 字符串
//             String publicKeyBase64 = kv.getKey();
//             // kv.getValue() 是 phiBase64 字符串的字节表示
//             String phiBase64 = new String(kv.getValue(), StandardCharsets.UTF_8);

//             // ***** 可以选择是否将它们转换回 Element，这里为了与原逻辑保持一致，仍进行转换 *****
//             Element publicKeyElement = base64StringToElement(publicKeyBase64);
//             Element phiElement = base64StringToElement(phiBase64);

//             mapping.put("publicKey", elementToBase64String(publicKeyElement)); // 确保是 Element 再转 Base64
//             mapping.put("phi", elementToBase64String(phiElement)); // 确保是 Element 再转 Base64
//             allMappings.add(mapping);
//         });

//         return GSON.toJson(allMappings);
//     }

//     // ---------------------------- Main 方法 (用于本地运行和调试) ----------------------------
//     /**
//      * Main 方法用于在本地测试或作为链码入口点启动。
//      * 当链码部署到 Fabric 网络时，Fabric peer 会调用这个 main 方法来启动链码。
//      */
//     public static void main(String[] args) {
//         System.out.println("Starting DVASChaincode...");
//         // 调用 ChaincodeBase 的 start 方法来启动链码监听器
//         new DVASChaincode().start(args);
//     }
// }