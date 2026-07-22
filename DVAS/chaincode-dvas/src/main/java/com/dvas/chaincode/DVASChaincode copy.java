// package com.dvas.chaincode;

// import org.hyperledger.fabric.contract.Context;
// import org.hyperledger.fabric.contract.ContractBase;
// import org.hyperledger.fabric.contract.annotation.Contract;
// import org.hyperledger.fabric.contract.annotation.Default;
// import org.hyperledger.fabric.contract.annotation.Info;
// import org.hyperledger.fabric.contract.annotation.License;
// import org.hyperledger.fabric.contract.annotation.Transaction;
// import org.hyperledger.fabric.shim.ChaincodeStub;

// import it.unisa.dia.gas.jpbc.Element;
// import it.unisa.dia.gas.jpbc.Pairing;
// import it.unisa.dia.gas.jpbc.PairingParameters;
// import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
// import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator; // <-- 引入这个

// import java.util.Base64;
// import java.util.ArrayList;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;
// import com.google.gson.Gson; // 用于 JSON 序列化/反序列化
// import com.google.gson.reflect.TypeToken; // 用于解析 JSON 数组，如果需要 addSensorMapBatch
// import java.nio.charset.StandardCharsets; // <-- 添加此行，用于处理字节编码


// @Contract(
//         name = "DVASChaincode",
//         info = @Info(
//                 title = "DVAS Chaincode",
//                 description = "Chaincode for DVAS system's public key and phi_i mappings",
//                 version = "1.0.0",
//                 license = @License(name = "Apache-2.0"),
//                 contact = @org.hyperledger.fabric.contract.annotation.Contact(
//                         email = "your.email@example.com",
//                         name = "Your Name"
//                 ))
// )
// @Default
// public class DVASChaincode extends ContractBase {

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

//     /**
//      * 初始化链码 (可选，如果需要预置数据)
//      */
//     @Transaction()
//     public void InitLedger(final Context ctx) {
//         System.out.println("DVAS Chaincode initialized.");
//     }

//     /**
//      * 替换 Blockchain.addSensorMap() 中的单个 publicKey -> phi_i 映射。
//      * 由于 Blockchain.java 中的 getPhiByPublicKey 是全局遍历的，所以我们将 PublicKey 作为账本的键。
//      *
//      * @param ctx              事务上下文
//      * @param publicKeyBase64  Base64 编码的 PublicKey Element
//      * @param phiBase64        Base64 编码的 Phi_i Element
//      * @return 成功消息
//      */
//     @Transaction()
//     public String addMapping(final Context ctx, String publicKeyBase64, String phiBase64) {
//         ChaincodeStub stub = ctx.getStub();

//         if (publicKeyBase64 == null || publicKeyBase64.isEmpty() || phiBase64 == null || phiBase64.isEmpty()) {
//             throw new RuntimeException("Public key and phi_i cannot be empty");
//         }

//         // 将 Base64 字符串转回 Element 字节数组进行存储
//         // 账本键是 PublicKey 的字节数组，值是 Phi_i 的字节数组
//         stub.putState(publicKeyBase64, base64StringToElement(phiBase64).toBytes());

//         System.out.println(String.format("Mapping added: PublicKey [%s] -> Phi_i [%s]", publicKeyBase64, phiBase64));
//         return "Mapping added successfully.";
//     }

//     /**
//      * 替换 Blockchain.getPhiByPublicKey()。
//      * 根据公钥查询对应的 phi_i。
//      *
//      * @param ctx              事务上下文
//      * @param publicKeyBase64  Base64 编码的 PublicKey Element
//      * @return Base64 编码的 Phi_i Element，如果未找到则返回 null。
//      */
//     @Transaction(intent = Transaction.TYPE.EVALUATE) // 查询交易
//     public String queryPhi(final Context ctx, String publicKeyBase64) {
//         ChaincodeStub stub = ctx.getStub();

//         if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
//             throw new RuntimeException("Public key cannot be empty");
//         }

//         // 使用 PublicKey 的字节数组作为键进行查询
//         byte[] phiBytes = stub.getState(publicKeyBase64);

//         if (phiBytes == null || phiBytes.length == 0) {
//             System.out.println(String.format("Phi_i not found for PublicKey [%s]", publicKeyBase64));
//             return null;
//         }

//         // 将查询到的字节数组转回 Element，然后 Base64 编码后返回
//         Element phi = pairing.getG1().newElementFromBytes(phiBytes).getImmutable(); // 假设 Phi_i 也在 G1 群
//         System.out.println(String.format("Phi_i found: PublicKey [%s] -> Phi_i [%s]", publicKeyBase64, elementToBase64String(phi)));
//         return elementToBase64String(phi);
//     }

//     /**
//      * 替换 Blockchain.getAllSensorMaps() / printBlockchain() 的部分功能。
//      * 返回所有存储的 (PublicKey, Phi_i) 映射。
//      * 注意：对于大量数据，这可能效率低下。
//      * @param ctx 事务上下文
//      * @return 包含所有映射的 JSON 字符串。
//      */
//     @Transaction(intent = Transaction.TYPE.EVALUATE)
//     public String queryAllMappings(final Context ctx) {
//         ChaincodeStub stub = ctx.getStub();
//         List<Map<String, String>> allMappings = new ArrayList<>();

//         // 遍历所有键值对。在 Fabric 中，这是一个迭代器，获取所有键值对
//         stub.getStateByRange("", "").forEach(kv -> {
//             Map<String, String> mapping = new HashMap<>();
//             // 键是 PublicKey 的字节数组，值是 Phi_i 的字节数组
//             Element publicKey = pairing.getG1().newElementFromBytes(kv.getKey().getBytes(StandardCharsets.UTF_8)).getImmutable();
//             Element phi = pairing.getG1().newElementFromBytes(kv.getValue()).getImmutable();
//             mapping.put("publicKey", elementToBase64String(publicKey));
//             mapping.put("phi", elementToBase64String(phi));
//             allMappings.add(mapping);
//         });

//         return GSON.toJson(allMappings); // 使用 Gson 将 List<Map<String, String>> 转换为 JSON 字符串
//     }

//     // 如果需要批量添加一个“传感器 Map”中的所有映射，可以实现这个方法
//     // @Transaction()
//     // public String addSensorMapBatch(final Context ctx, String jsonMappings) {
//     //     // 假设 jsonMappings 是一个 JSON 数组字符串，例如：
//     //     // '[{"publicKey": "pkBase64_1", "phi": "phiBase64_1"}, {"publicKey": "pkBase64_2", "phi": "phiBase64_2"}]'
//     //     List<Map<String, String>> mappings = GSON.fromJson(jsonMappings, new TypeToken<List<Map<String, String>>>(){}.getType());
//     //
//     //     for (Map<String, String> mapping : mappings) {
//     //         addMapping(ctx, mapping.get("publicKey"), mapping.get("phi"));
//     //     }
//     //     return "Batch mappings added successfully.";
//     // }
// }