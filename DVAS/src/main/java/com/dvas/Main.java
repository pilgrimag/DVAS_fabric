package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.nio.file.Files; // 确保 Files 类被导入
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

public class Main {

    private static final String CHANNEL_NAME = "mychannel";
    private static final String CHAINCODE_NAME = "chaincode";
    private static final int NUM_RUNS = 20; // 运行次数，用于取平均。根据表格要求设置为20。

    // 用于收集每个阶段的执行时间 (每个List的一个元素代表一个回合的总时间)
    private static List<Long> setupTimes = new ArrayList<>();
    private static List<Long> joinTimes = new ArrayList<>();
    private static List<Long> signTimes = new ArrayList<>(); // 每个回合的纯密码学签名总时间
    private static List<Long> blockchainSubmitTimes = new ArrayList<>(); // 每个回合的区块链事务提交总时间
    
    // --- 新增：用于收集 Sanitizing 阶段细分时间 ---
    private static List<Long> sanitizingTotalTimes = new ArrayList<>(); // 每个回合的 Sanitizing 阶段总时间
    private static List<Long> sanitizingComputeTimes = new ArrayList<>(); // 每个回合的 Sanitizing 纯链下密码学计算总时间
    private static List<Long> sanitizingFabricQueryTimes = new ArrayList<>(); // 每个回合的 Sanitizing Fabric 链码查询总时间
    // ------------------------------------------

    private static List<Long> aggregateTimes = new ArrayList<>(); // 每个回合的聚合总时间
    private static List<Long> aggVerifyTimes = new ArrayList<>(); // 每个回合的聚合验证总时间

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // --- 配置测试参数 ---
        int totalMessages;
        int sensitiveMessages;

        if (args.length >= 2) {
            try {
                totalMessages = Integer.parseInt(args[0]);
                sensitiveMessages = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Error: Invalid number format for totalMessages or sensitiveMessages. Please provide integers.");
                System.err.println("Usage: mvn exec:java -Dexec.args=\"<totalMessages> <sensitiveMessages>\"");
                return;
            }
        } else {
            System.err.println("Error: Insufficient command-line arguments. Please provide totalMessages and sensitiveMessages.");
            System.err.println("Usage: mvn exec:java -Dexec.args=\"<totalMessages> <sensitiveMessages>\"");
            return;
        }

        System.out.println(String.format("Starting performance test for Total Messages: %d, Sensitive Messages: %d (Number of runs: %d)", totalMessages, sensitiveMessages, NUM_RUNS));

        // --- Fabric Gateway Setup (仅在所有测试开始前连接一次) ---
        Gateway gateway = null;
        Network network = null;
        Contract contract = null;
        try {
            Path walletPath = Paths.get("src", "main", "resources", "identities");
            Wallet wallet = Wallets.newFileSystemWallet(walletPath);

            String identityLabel = "Org1Admin";

            if (wallet.get(identityLabel) == null) {
                System.out.println("-----> Adding identity to wallet: " + identityLabel);
                Path certificatePath = Paths.get("src", "main", "resources", "identities", "Org1", "Admin", "cert.pem");
                Path privateKeyPath = Paths.get("src", "main", "resources", "identities", "Org1", "Admin", "priv_sk");

                X509Certificate certificate = Identities.readX509Certificate(certificatePath);
                PrivateKey privateKey = Identities.readPrivateKey(privateKeyPath);

                Identity identity = Identities.newX509Identity("Org1MSP", certificate, privateKey);
                wallet.put(identityLabel, identity);
                System.out.println("-----> Identity added successfully.");
            }

            Path networkConfigPath = Paths.get("src", "main", "resources", "connection-org1.json");

            Gateway.Builder builder = Gateway.createBuilder()
                    .identity(wallet, identityLabel)
                    .networkConfig(networkConfigPath)
                    .discovery(false); // Ensure service discovery is disabled

            gateway = builder.connect();
            network = gateway.getNetwork(CHANNEL_NAME);
            contract = network.getContract(CHAINCODE_NAME);

            System.out.println("\n--- Successfully connected to Fabric Network and Chaincode ---");
            System.out.println("Blockchain adapter initialized. Now starting performance measurements.");

            // --- 外部循环用于进行多次测量并取平均 ---
            for (int run = 0; run < NUM_RUNS; run++) {
                System.out.println(String.format("\n--- Starting Run %d/%d ---", run + 1, NUM_RUNS));

                Message M = new Message("zjl", "2025-1-7");

                List<Integer> FIX = new ArrayList<>();
                List<Integer> ADM = new ArrayList<>();
                List<Integer> Index = new ArrayList<>();
                List<Element> VList = new ArrayList<>();
                List<Element> PhiList = new ArrayList<>();
                List<Element> UiList = new ArrayList<>();
                List<Message> messages = new ArrayList<>();
                for (int i = 0; i < totalMessages; i++) { messages.add(new Message("zjl", "2025-1-7")); }
                List<com.dvas.Sign.Signature> signatures = new ArrayList<>();


                // --- 1. Setup Phase ---
                long setupStart = System.nanoTime();
                Setup setup = new Setup();
                Blockchain blockchain = new Blockchain(contract, setup.getPairing()); 

                SensorKeyPair[] sensorKeys = new SensorKeyPair[totalMessages];
                int[] sensorIDs = new int[totalMessages];
                for (int i = 0; i < totalMessages; i++) {
                    sensorIDs[i] = i;
                    sensorKeys[i] = setup.distributeKeyToSensor(sensorIDs[i]);
                }
                int edgeNodeID = 11;
                SensorKeyPair edgeNodeKey = setup.distributeKeyToEdgeNode(edgeNodeID);
                int dvNodeID = 111;
                SensorKeyPair dvNodeKey = setup.distributeKeyToDVNode(dvNodeID);
                long setupEnd = System.nanoTime();
                setupTimes.add(setupEnd - setupStart);
                // System.out.println(String.format("Setup Time: %.2f ms", (setupEnd - setupStart) / 1_000_000.0)); // 临时注释，统一在回合末尾打印

                // --- 2. Join Phase ---
                long joinStart = System.nanoTime();
                Join join = new Join(setup);
                for (int i = 0; i < totalMessages; i++) {
                    System.out.println("joining");
                    Index.add(i);
                    boolean isSensitive = (i < sensitiveMessages);
                    if (isSensitive) {
                        ADM.add(i);
                    } else {
                        FIX.add(i);
                    }
                    join.groupTask(i, isSensitive, ADM, FIX);
                }
                long joinEnd = System.nanoTime();
                joinTimes.add(joinEnd - joinStart);
                // System.out.println(String.format("Join Time: %.2f ms", (joinEnd - joinStart) / 1_000_000.0)); // 临时注释，统一在回合末尾打印


                // --- 3. Sign Phase (纯密码学签名 + 区块链提交) ---
                // 引入临时变量，累加当前回合的签名时间和提交时间
                long currentRunSignTimeTotal = 0;
                long currentRunBlockchainSubmitTimeTotal = 0;
                // System.out.println("sign");
                for (int i = 0; i < totalMessages; i++) {
                    // 3.1 纯密码学签名计算计时
                    System.out.println("signing");
                    long cryptoSignStart = System.nanoTime();
                    Sign sign_mul = new Sign(setup, sensorKeys[i]);
                    com.dvas.Sign.Signature sig_mul = sign_mul.generateSignature(
                        M, "2025-1-7", sensorIDs[i],
                        edgeNodeKey.getU_i(),
                        dvNodeKey.getU_i()
                    );
                    signatures.add(sig_mul);
                    VList.add(sig_mul.getV_i());
                    PhiList.add(sig_mul.getPhi_i());
                    long cryptoSignEnd = System.nanoTime();
                    currentRunSignTimeTotal += (cryptoSignEnd - cryptoSignStart); // 累加到当前回合总时间


                    // 3.2 区块链事务提交计时
                    long submitStart = System.nanoTime();
                    String publicKeyBase64 = elementToBase64String(sensorKeys[i].getU_i());
                    String phiBase64 = elementToBase64String(sig_mul.getPhi_i());
                    System.out.println("addmap前");
                    blockchain.addMapping(publicKeyBase64, phiBase64);
                    // System.out.println("addmap后");
                    long submitEnd = System.nanoTime();
                    currentRunBlockchainSubmitTimeTotal += (submitEnd - submitStart); // 累加到当前回合总时间
                }
                signTimes.add(currentRunSignTimeTotal);           // 将当前回合的纯签名总时间添加到 List
                blockchainSubmitTimes.add(currentRunBlockchainSubmitTimeTotal); // 将当前回合的区块链提交总时间添加到 List


                // --- 4. Sanitizing Phase ---
                long sanitizingTotalStart = System.nanoTime(); // 计时 Sanitizing 阶段总时间
                SanitizingStage ver_mul = new SanitizingStage(setup);
                Map<Integer, Element> UiMap = new HashMap<>();

                long currentRunComputeTime = 0;    // 当前运行轮次中 Sanitizing 的纯链下计算总时间
                long currentRunFabricQueryTime = 0; // 当前运行轮次中 Sanitizing 的 Fabric 查询总时间

                for (int i = 0; i < signatures.size(); i++) {
                    Element publicKey = sensorKeys[i].getU_i().getImmutable();
                    UiList.add(publicKey);
                    UiMap.put(i, publicKey);

                    SanitizingStage.SanitizingSubTimings subTimings = ver_mul.verifySignature(
                        setup,
                        publicKey,
                        UiList,
                        edgeNodeKey.getu_i(),
                        messages.get(i),
                        signatures.get(i),
                        setup.getP(),
                        dvNodeKey.getU_i(),
                        blockchain, 
                        ADM
                    );
                    currentRunComputeTime += subTimings.offChainComputeTime;     // 累加纯链下计算时间
                    currentRunFabricQueryTime += subTimings.fabricQueryTime;    // 累加 Fabric 查询时间
                }
                long sanitizingTotalEnd = System.nanoTime();

                sanitizingTotalTimes.add(sanitizingTotalEnd - sanitizingTotalStart); // 收集总时间
                sanitizingComputeTimes.add(currentRunComputeTime); // 收集纯链下计算总时间
                sanitizingFabricQueryTimes.add(currentRunFabricQueryTime); // 收集 Fabric 查询总时间

                // System.out.println(String.format("Sanitizing Time (Total): %.2f ms", (sanitizingTotalEnd - sanitizingTotalStart) / 1_000_000.0)); // 临时注释，统一在回合末尾打印

                // --- 5. Aggregate Phase ---
                long aggregateStart = System.nanoTime();
                Aggregate agg = new Aggregate(setup);
                Aggregate.AggregateResult aggResult = agg.computeAggregate(setup, setup.getP(), dvNodeKey.getU_i(), signatures, sensorIDs, ADM, FIX, new HashMap<>(), new ArrayList<>(), Index);
                long aggregateEnd = System.nanoTime();
                aggregateTimes.add(aggregateEnd - aggregateStart);
                // System.out.println(String.format("Aggregate Time (Off-chain): %.2f ms", (aggregateEnd - aggregateStart) / 1_000_000.0)); // 临时注释，统一在回合末尾打印

                // --- 6. AggVerify Phase ---
                long aggVerifyStart = System.nanoTime();
                AggVerify aggVerify = new AggVerify(setup);
                boolean aggres = aggVerify.verifyAggregate(setup, aggResult.getT(), setup.getP(), edgeNodeKey.getU_i(), dvNodeKey.getu_i(), aggResult.getZ(), FIX, ADM, messages, UiMap, aggResult, PhiList, totalMessages, Index, UiList, VList, new ArrayList<>());
                long aggVerifyEnd = System.nanoTime();
                aggVerifyTimes.add(aggVerifyEnd - aggVerifyStart);
                // System.out.println(String.format("Agg Verify Time (Off-chain): %.2f ms", (aggVerifyEnd - aggVerifyStart) / 1_000_000.0)); // 临时注释，统一在回合末尾打印


                // --- 在每个回合结束时，统一打印所有指标 ---
                System.out.println(String.format("Setup Time:       %.2f ms", (setupEnd - setupStart) / 1_000_000.0));
                System.out.println(String.format("Join Time:        %.2f ms", (joinEnd - joinStart) / 1_000_000.0));
                System.out.println(String.format("Sign Time (Pure Crypto): %.2f ms", currentRunSignTimeTotal / 1_000_000.0));
                System.out.println(String.format("Blockchain Submit Time: %.2f ms", currentRunBlockchainSubmitTimeTotal / 1_000_000.0));
                System.out.println(String.format("Sanitizing Total Time: %.2f ms", (sanitizingTotalEnd - sanitizingTotalStart) / 1_000_000.0));
                System.out.println(String.format("  - Sanitizing Compute Time (Off-chain): %.2f ms", currentRunComputeTime / 1_000_000.0));
                System.out.println(String.format("  - Sanitizing Fabric Query Time: %.2f ms", currentRunFabricQueryTime / 1_000_000.0));
                System.out.println(String.format("Aggregate Time (Off-chain): %.2f ms", (aggregateEnd - aggregateStart) / 1_000_000.0));
                System.out.println(String.format("Agg Verify Time (Off-chain): %.2f ms", (aggVerifyEnd - aggVerifyStart) / 1_000_000.0));
                System.out.println("Aggregate Verification Result (Off-chain): " + aggres);


            } // End of NUM_RUNS loop

        } catch (Exception e) {
            System.err.println("Fatal error during Fabric interaction: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (gateway != null) {
                gateway.close(); // 所有测试运行完毕后，关闭 Gateway 连接
                System.out.println("--- Gateway connection closed ---"); 
            }
        }

        // 计算并打印平均值
        System.out.println("\n--- Average Performance Results (over " + NUM_RUNS + " runs) ---");
        System.out.println(String.format("Average Setup Time:       %.2f ms", calculateAverage(setupTimes)));
        System.out.println(String.format("Average Join Time:        %.2f ms", calculateAverage(joinTimes)));
        System.out.println(String.format("Average Sign Time (Pure Crypto): %.2f ms", calculateAverage(signTimes))); 
        System.out.println(String.format("Average Blockchain Submit Time: %.2f ms", calculateAverage(blockchainSubmitTimes)));
        
        // --- 打印 Sanitizing 阶段的细分平均值 ---
        System.out.println(String.format("Average Sanitizing Total Time: %.2f ms", calculateAverage(sanitizingTotalTimes)));
        System.out.println(String.format("  - Average Sanitizing Compute Time (Off-chain): %.2f ms", calculateAverage(sanitizingComputeTimes)));
        System.out.println(String.format("  - Average Sanitizing Fabric Query Time: %.2f ms", calculateAverage(sanitizingFabricQueryTimes)));
        // ------------------------------------------

        System.out.println(String.format("Average Aggregate Time:   %.2f ms", calculateAverage(aggregateTimes)));
        System.out.println(String.format("Average AggVerify Time:   %.2f ms", calculateAverage(aggVerifyTimes)));
    }

    private static double calculateAverage(List<Long> times) {
        if (times.isEmpty()) {
            return 0.0;
        }
        long sum = 0;
        for (Long time : times) {
            sum += time;
        }
        return (double) sum / times.size() / 1_000_000.0; // 转换为毫秒
    }

    // Auxiliary method: Element to Base64 String
    private static String elementToBase64String(Element element) {
        if (element == null) return null;
        byte[] bytes = element.toBytes();
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Identities 类保持不变 (已省略，假设你已拥有此部分代码)
    static class Identities {
        public static X509Certificate readX509Certificate(Path certificatePath) throws IOException {
            try (java.io.Reader certReader = Files.newBufferedReader(certificatePath, StandardCharsets.UTF_8)) {
                org.bouncycastle.openssl.PEMParser pemParser = new org.bouncycastle.openssl.PEMParser(certReader);
                Object parsedObject = pemParser.readObject();
                return (X509Certificate) new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate((X509CertificateHolder) parsedObject);
            } catch (Exception e) {
                throw new IOException("Failed to read certificate from " + certificatePath, e);
            }
        }

        public static PrivateKey readPrivateKey(Path privateKeyPath) throws IOException {
            try (java.io.Reader keyReader = Files.newBufferedReader(privateKeyPath, StandardCharsets.UTF_8)) {
                org.bouncycastle.openssl.PEMParser pemParser = new org.bouncycastle.openssl.PEMParser(keyReader);
                Object parsedObject = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
                if (parsedObject instanceof PEMKeyPair) {
                    return converter.getPrivateKey(((PEMKeyPair) parsedObject).getPrivateKeyInfo());
                } else if (parsedObject instanceof PrivateKeyInfo) {
                    return converter.getPrivateKey((PrivateKeyInfo) parsedObject);
                } else {
                    throw new IOException("Unable to read private key from " + privateKeyPath + ". Unknown object type: " + parsedObject.getClass().getName());
                }
            } catch (Exception e) {
                throw new IOException("Failed to read private key from " + privateKeyPath, e);
            }
        }
        public static Identity newX509Identity(String mspId, X509Certificate certificate, PrivateKey privateKey) {
            return org.hyperledger.fabric.gateway.Identities.newX509Identity(mspId, certificate, privateKey);
        }
    }
}
