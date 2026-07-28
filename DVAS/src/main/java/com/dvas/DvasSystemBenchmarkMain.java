package com.dvas;

import com.dvas.Aggregate.AggregateResult;
import com.dvas.Sign.Signature;
import com.dvas.sendToEN.Send;
import it.unisa.dia.gas.jpbc.Element;
import org.hyperledger.fabric.client.Contract;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Real-Fabric system benchmark for DVAS Fig.9-Fig.13.
 *
 * <p>Fig.9 records application-payload communication bytes.
 * Fig.10 records the aggregate evidence bytes required by the
 * designated verifier. Fig.11 records chaincode key/value bytes.
 * Fig.12 is N/A because DVAS has no native off-chain storage path.
 * Fig.13 records the real online path with Fabric submit/query.</p>
 */
public final class DvasSystemBenchmarkMain {

    private static final String CSV_NAME =
            "dvas-system-raw.csv";

    private static final String METADATA_NAME =
            "dvas-system-metadata.txt";

    private static final String VALIDATION_NAME =
            "VALIDATION";

    private static final int REPORT_SIZE_BYTES = 1024;

    private static final int[] FULL_SIZE_SWEEP = {
        50, 100, 200, 400, 600, 800, 1000
    };

    private static final String CSV_HEADER =
            "scheme,experiment,profile,run,n,ns,mode,"
                    + "report_size_bytes,sensor_to_en_bytes,"
                    + "fabric_mapping_bytes,en_to_dv_bytes,"
                    + "total_communication_bytes,"
                    + "aggregate_evidence_bytes,"
                    + "onchain_application_bytes,"
                    + "offchain_storage_bytes,"
                    + "offchain_store_ns,offchain_fetch_ns,"
                    + "sign_ns,fabric_add_mapping_ns,"
                    + "fabric_query_phi_ns,sigverify_ns,"
                    + "privacy_ns,aggregate_ns,aggverify_ns,"
                    + "total_e2e_ns,"
                    + "throughput_reports_per_s,"
                    + "accepted_count,correctness";

    private static final String POLICY =
            "DVAS-POLICY-V1";

    private DvasSystemBenchmarkMain() {
    }

    public static void main(
            final String[] args) throws Exception {

        if (args.length != 2) {
            throw new IllegalArgumentException(
                    "Usage: DvasSystemBenchmarkMain "
                            + "<output-directory> <smoke|full>"
            );
        }

        final Path outputDirectory =
                Path.of(args[0])
                        .toAbsolutePath()
                        .normalize();

        final Profile profile =
                Profile.parse(args[1]);

        if (Files.exists(outputDirectory)) {
            throw new IllegalStateException(
                    "Output directory already exists: "
                            + outputDirectory
            );
        }

        Files.createDirectories(outputDirectory);

        final List<Scenario> scenarios =
                scenariosFor(profile);

        final int maximumN =
                scenarios.stream()
                        .mapToInt(Scenario::n)
                        .max()
                        .orElseThrow();

        System.out.printf(
                Locale.ROOT,
                "DVAS system benchmark: profile=%s, "
                        + "scenarios=%d, warmups=%d, "
                        + "measurements=%d, maxN=%d%n",
                profile.name,
                scenarios.size(),
                profile.warmupRuns,
                profile.measurementRuns,
                maximumN
        );

        final Instant createdUtc = Instant.now();
        final long setupStart = System.nanoTime();
        final Environment environment =
                Environment.create(maximumN);
        final long setupNs =
                System.nanoTime() - setupStart;

        final Path csvPath =
                outputDirectory.resolve(CSV_NAME);

        int writtenRows = 0;

        try (
            FabricGatewayConnection gateway =
                    FabricGatewayConnection.connect();
            BufferedWriter writer =
                    Files.newBufferedWriter(
                            csvPath,
                            StandardCharsets.UTF_8
                    )
        ) {
            final Contract contract =
                    gateway.getContract();

            final Blockchain blockchain =
                    new Blockchain(
                            contract,
                            environment.setup.getPairing()
                    );

            writer.write(CSV_HEADER);
            writer.newLine();

            for (
                int scenarioIndex = 0;
                scenarioIndex < scenarios.size();
                scenarioIndex++
            ) {
                final Scenario scenario =
                        scenarios.get(scenarioIndex);

                System.out.printf(
                        Locale.ROOT,
                        "[%d/%d] experiment=system_size_sweep, "
                                + "n=%d, mode=%s%n",
                        scenarioIndex + 1,
                        scenarios.size(),
                        scenario.n,
                        scenario.mode.csvValue
                );

                settleBetweenScenarios();

                for (
                    int warmup = 1;
                    warmup <= profile.warmupRuns;
                    warmup++
                ) {
                    executeTrial(
                            environment,
                            blockchain,
                            scenario,
                            -warmup
                    );
                }

                for (
                    int run = 1;
                    run <= profile.measurementRuns;
                    run++
                ) {
                    final TrialResult result =
                            executeTrial(
                                    environment,
                                    blockchain,
                                    scenario,
                                    run
                            );

                    validateTrial(
                            scenario,
                            result
                    );

                    writer.write(
                            result.toCsv(
                                    profile.name,
                                    scenario,
                                    run
                            )
                    );
                    writer.newLine();
                    writer.flush();
                    writtenRows++;
                }
            }
        }

        final int expectedRows =
                Math.multiplyExact(
                        scenarios.size(),
                        profile.measurementRuns
                );

        if (writtenRows != expectedRows) {
            throw new IllegalStateException(
                    "Unexpected row count: "
                            + writtenRows
                            + ", expected "
                            + expectedRows
            );
        }

        writeMetadata(
                outputDirectory.resolve(
                        METADATA_NAME
                ),
                createdUtc,
                profile,
                scenarios,
                writtenRows,
                setupNs
        );

        writeValidation(
                outputDirectory.resolve(
                        VALIDATION_NAME
                ),
                profile,
                scenarios,
                writtenRows
        );

        System.out.println(
                "DVAS system benchmark: PASS"
        );
        System.out.println(
                "csv=" + csvPath
        );
        System.out.println(
                "rows=" + writtenRows
        );
        System.out.println(
                "scenarios=" + scenarios.size()
        );
        System.out.println(
                "fabric_included=true"
        );
        System.out.println(
                "ipfs_included=false"
        );
    }

    private static TrialResult executeTrial(
            final Environment environment,
            final Blockchain blockchain,
            final Scenario scenario,
            final int runOrdinal) throws Exception {

        final int n = scenario.n;
        final int ns =
                scenario.mode == Mode.ALL_ADM
                        ? n
                        : 0;

        final List<Integer> adm =
                new ArrayList<>(ns);

        final List<Integer> fix =
                new ArrayList<>(n - ns);

        final List<Integer> index =
                new ArrayList<>(n);

        final int[] sensorIds =
                new int[n];

        final List<Message> messages =
                new ArrayList<>(n);

        final List<String> originalMessages =
                new ArrayList<>(n);

        final List<Signature> signatures =
                new ArrayList<>(n);

        final List<Element> phiList =
                new ArrayList<>(n);

        final List<Element> uiList =
                new ArrayList<>(n);

        final List<Element> vList =
                new ArrayList<>(n);

        final Map<Integer, Element> uiMap =
                new HashMap<>(mapCapacity(n));

        for (int i = 0; i < n; i++) {
            sensorIds[i] = i;
            index.add(i);

            if (scenario.mode == Mode.ALL_ADM) {
                adm.add(i);
            } else {
                fix.add(i);
            }

            final String report =
                    createAsciiReport(
                            scenario,
                            runOrdinal,
                            i
                    );

            messages.add(
                    new Message(
                            report,
                            POLICY
                    )
            );

            originalMessages.add(report);

            final Element publicKey =
                    environment.sensorKeys[i]
                            .getU_i()
                            .getImmutable();

            uiList.add(publicKey);
            uiMap.put(i, publicKey);
        }

        final long signStart =
                System.nanoTime();

        for (int i = 0; i < n; i++) {
            final Signature signature =
                    environment.signers[i]
                            .generateSignature(
                                    messages.get(i),
                                    messages.get(i)
                                            .getOmega(),
                                    i,
                                    environment.edgeKey
                                            .getU_i(),
                                    environment.dvKey
                                            .getU_i()
                            );

            signatures.add(signature);
            phiList.add(
                    signature.getPhi_i()
                            .getImmutable()
            );
            vList.add(
                    signature.getV_i()
                            .getImmutable()
            );
        }

        final long signNs =
                System.nanoTime() - signStart;

        final long sensorToEnBytes =
                sensorToEnBytes(
                        messages,
                        signatures
                );

        long fabricMappingBytes = 0;

        final long submitStart =
                System.nanoTime();

        for (int i = 0; i < n; i++) {
            final String publicKeyBase64 =
                    blockchain.elementToBase64String(
                            uiList.get(i)
                    );

            final String phiBase64 =
                    blockchain.elementToBase64String(
                            phiList.get(i)
                    );

            fabricMappingBytes =
                    Math.addExact(
                            fabricMappingBytes,
                            utf8Length(publicKeyBase64)
                                    + utf8Length(phiBase64)
                    );

            blockchain.addMapping(
                    publicKeyBase64,
                    phiBase64
            );
        }

        final long fabricAddMappingNs =
                System.nanoTime() - submitStart;

        final List<Element> queriedPhi =
                new ArrayList<>(n);

        final long queryStart =
                System.nanoTime();

        for (int i = 0; i < n; i++) {
            final Element phi =
                    blockchain.getPhiByPublicKey(
                            uiList.get(i)
                    );

            if (phi == null) {
                throw new IllegalStateException(
                        "Fabric query returned null: "
                                + "sensor=" + i
                );
            }

            queriedPhi.add(phi);
        }

        final long fabricQueryPhiNs =
                System.nanoTime() - queryStart;

        for (int i = 0; i < n; i++) {
            if (
                !queriedPhi.get(i)
                        .isEqual(phiList.get(i))
            ) {
                throw new IllegalStateException(
                        "Fabric mapping mismatch: "
                                + "sensor=" + i
                );
            }
        }

        int acceptedCount = 0;

        final long verifyStart =
                System.nanoTime();

        for (int i = 0; i < n; i++) {
            final boolean accepted =
                    environment.sanitizingStage
                            .verifyOriginalSignatureOffChain(
                                    uiList.get(i),
                                    messages.get(i),
                                    signatures.get(i),
                                    environment.setup
                                            .getP(),
                                    queriedPhi.get(i)
                            );

            if (!accepted) {
                throw new IllegalStateException(
                        "Original signature rejected: "
                                + "sensor=" + i
                );
            }

            acceptedCount++;
        }

        final long sigverifyNs =
                System.nanoTime() - verifyStart;

        long privacyNs = 0;

        if (scenario.mode == Mode.ALL_ADM) {
            final long privacyStart =
                    System.nanoTime();

            for (int i = 0; i < n; i++) {
                environment.sanitizingStage
                        .sanitizeVerifiedSignatureOffChain(
                                uiList.get(i),
                                environment.edgeKey
                                        .getu_i(),
                                messages.get(i),
                                signatures.get(i),
                                environment.setup
                                        .getP(),
                                environment.dvKey
                                        .getU_i()
                        );
            }

            privacyNs =
                    System.nanoTime()
                            - privacyStart;
        }

        validateSanitization(
                scenario.mode,
                originalMessages,
                messages
        );

        final long aggregateStart =
                System.nanoTime();

        final AggregateResult aggregateResult =
                environment.aggregate
                        .computeAggregate(
                                environment.setup,
                                environment.setup.getP(),
                                environment.dvKey
                                        .getU_i(),
                                signatures,
                                sensorIds,
                                adm,
                                fix,
                                new HashMap<>(),
                                List.of(),
                                index
                        );

        final long aggregateNs =
                System.nanoTime()
                        - aggregateStart;

        if (
            aggregateResult == null
                    || aggregateResult.getT() == null
                    || aggregateResult.getZ() == null
                    || aggregateResult.getVMap() == null
                    || aggregateResult.getVMap().size()
                            != n
        ) {
            throw new IllegalStateException(
                    "Aggregate generation failed."
            );
        }

        final long aggregateEvidenceBytes =
                aggregateEvidenceBytes(
                        aggregateResult,
                        n
                );

        final long enToDvBytes =
                enToDvBytes(
                        messages,
                        aggregateEvidenceBytes
                );

        final long totalCommunicationBytes =
                Math.addExact(
                        Math.addExact(
                                sensorToEnBytes,
                                fabricMappingBytes
                        ),
                        enToDvBytes
                );

        final long aggverifyStart =
                System.nanoTime();

        final boolean aggregateAccepted =
                environment.aggVerify
                        .verifyAggregate(
                                environment.setup,
                                aggregateResult.getT(),
                                environment.setup.getP(),
                                environment.edgeKey
                                        .getU_i(),
                                environment.dvKey
                                        .getu_i(),
                                aggregateResult.getZ(),
                                fix,
                                adm,
                                messages,
                                uiMap,
                                aggregateResult,
                                phiList,
                                n,
                                index,
                                uiList,
                                vList,
                                List.<Send>of()
                        );

        final long aggverifyNs =
                System.nanoTime()
                        - aggverifyStart;

        if (!aggregateAccepted) {
            throw new IllegalStateException(
                    "Aggregate signature rejected: "
                            + "n=" + n
                            + ", mode="
                            + scenario.mode.csvValue
            );
        }

        final long totalE2eNs =
                Math.addExact(
                        Math.addExact(
                                signNs,
                                fabricAddMappingNs
                        ),
                        Math.addExact(
                                Math.addExact(
                                        fabricQueryPhiNs,
                                        sigverifyNs
                                ),
                                Math.addExact(
                                        privacyNs,
                                        Math.addExact(
                                                aggregateNs,
                                                aggverifyNs
                                        )
                                )
                        )
                );

        final double throughput =
                n * 1_000_000_000.0
                        / totalE2eNs;

        return new TrialResult(
                sensorToEnBytes,
                fabricMappingBytes,
                enToDvBytes,
                totalCommunicationBytes,
                aggregateEvidenceBytes,
                fabricMappingBytes,
                signNs,
                fabricAddMappingNs,
                fabricQueryPhiNs,
                sigverifyNs,
                privacyNs,
                aggregateNs,
                aggverifyNs,
                totalE2eNs,
                throughput,
                acceptedCount,
                true
        );
    }

    private static long sensorToEnBytes(
            final List<Message> messages,
            final List<Signature> signatures) {

        long total = 0;

        for (int i = 0; i < messages.size(); i++) {
            total = Math.addExact(
                    total,
                    utf8Length(messages.get(i).getM())
                            + utf8Length(
                                    messages.get(i)
                                            .getOmega()
                            )
                            + Integer.BYTES
                            + elementLength(
                                    signatures.get(i)
                                            .getT_i()
                            )
                            + elementLength(
                                    signatures.get(i)
                                            .getV_i()
                            )
            );
        }

        return total;
    }

    private static long aggregateEvidenceBytes(
            final AggregateResult result,
            final int n) {

        long total =
                elementLength(result.getT())
                        + elementLength(
                                result.getZ()
                        );

        for (
            Map.Entry<Integer, Element> entry :
            result.getVMap().entrySet()
        ) {
            total = Math.addExact(
                    total,
                    Integer.BYTES
                            + elementLength(
                                    entry.getValue()
                            )
                            + Byte.BYTES
            );
        }

        if (result.getVMap().size() != n) {
            throw new IllegalStateException(
                    "Unexpected VMap size."
            );
        }

        return total;
    }

    private static long enToDvBytes(
            final List<Message> messages,
            final long aggregateEvidenceBytes) {

        long total = aggregateEvidenceBytes;

        for (Message message : messages) {
            total = Math.addExact(
                    total,
                    utf8Length(message.getM())
                            + utf8Length(
                                    message.getOmega()
                            )
                            + Integer.BYTES
            );
        }

        return total;
    }

    private static int utf8Length(
            final String value) {

        return value.getBytes(
                StandardCharsets.UTF_8
        ).length;
    }

    private static int elementLength(
            final Element element) {

        return element.toBytes().length;
    }

    private static void validateSanitization(
            final Mode mode,
            final List<String> originals,
            final List<Message> messages) {

        for (int i = 0; i < messages.size(); i++) {
            final String original =
                    originals.get(i);

            final String current =
                    messages.get(i).getM();

            if (mode == Mode.ALL_ADM) {
                if (current.equals(original)) {
                    throw new IllegalStateException(
                            "ADM message was not sanitized: "
                                    + i
                    );
                }

                if (
                    current.length()
                            != original.length()
                ) {
                    throw new IllegalStateException(
                            "ADM message length changed: "
                                    + i
                    );
                }

                if (
                    !current.chars()
                            .allMatch(
                                    value ->
                                            value == '*'
                            )
                ) {
                    throw new IllegalStateException(
                            "ADM message contains "
                                    + "non-mask characters: "
                                    + i
                    );
                }
            } else if (!current.equals(original)) {
                throw new IllegalStateException(
                        "FIX message was modified: "
                                + i
                );
            }
        }
    }

    private static void validateTrial(
            final Scenario scenario,
            final TrialResult result) {

        if (
            result.sensorToEnBytes <= 0
                    || result.fabricMappingBytes <= 0
                    || result.enToDvBytes <= 0
                    || result.totalCommunicationBytes <= 0
                    || result.aggregateEvidenceBytes <= 0
                    || result.onchainApplicationBytes <= 0
        ) {
            throw new IllegalStateException(
                    "All byte metrics must be positive."
            );
        }

        final long expectedCommunication =
                Math.addExact(
                        Math.addExact(
                                result.sensorToEnBytes,
                                result.fabricMappingBytes
                        ),
                        result.enToDvBytes
                );

        if (
            result.totalCommunicationBytes
                    != expectedCommunication
        ) {
            throw new IllegalStateException(
                    "total_communication_bytes mismatch"
            );
        }

        if (
            result.onchainApplicationBytes
                    != result.fabricMappingBytes
        ) {
            throw new IllegalStateException(
                    "onchain_application_bytes mismatch"
            );
        }

        if (
            result.signNs <= 0
                    || result.fabricAddMappingNs <= 0
                    || result.fabricQueryPhiNs <= 0
                    || result.sigverifyNs <= 0
                    || result.aggregateNs <= 0
                    || result.aggverifyNs <= 0
                    || result.totalE2eNs <= 0
        ) {
            throw new IllegalStateException(
                    "Required timing metrics "
                            + "must be positive."
            );
        }

        if (
            scenario.mode == Mode.ALL_FIX
                    && result.privacyNs != 0
        ) {
            throw new IllegalStateException(
                    "allfix privacy_ns must be zero"
            );
        }

        if (
            scenario.mode == Mode.ALL_ADM
                    && result.privacyNs <= 0
        ) {
            throw new IllegalStateException(
                    "alladm privacy_ns must be positive"
            );
        }

        final long expectedE2e =
                Math.addExact(
                        Math.addExact(
                                result.signNs,
                                result.fabricAddMappingNs
                        ),
                        Math.addExact(
                                Math.addExact(
                                        result.fabricQueryPhiNs,
                                        result.sigverifyNs
                                ),
                                Math.addExact(
                                        result.privacyNs,
                                        Math.addExact(
                                                result.aggregateNs,
                                                result.aggverifyNs
                                        )
                                )
                        )
                );

        if (result.totalE2eNs != expectedE2e) {
            throw new IllegalStateException(
                    "total_e2e_ns mismatch"
            );
        }

        if (
            result.acceptedCount != scenario.n
                    || !result.correctness
        ) {
            throw new IllegalStateException(
                    "Correctness validation failed."
            );
        }

        if (
            !Double.isFinite(result.throughput)
                    || result.throughput <= 0.0
        ) {
            throw new IllegalStateException(
                    "Invalid throughput."
            );
        }
    }

    private static List<Scenario> scenariosFor(
            final Profile profile) {

        final List<Scenario> scenarios =
                new ArrayList<>();

        final int[] sizes =
                profile == Profile.FULL
                        ? FULL_SIZE_SWEEP
                        : new int[] {2, 4};

        for (int n : sizes) {
            scenarios.add(
                    new Scenario(
                            n,
                            Mode.ALL_FIX
                    )
            );
            scenarios.add(
                    new Scenario(
                            n,
                            Mode.ALL_ADM
                    )
            );
        }

        return List.copyOf(scenarios);
    }

    private static String createAsciiReport(
            final Scenario scenario,
            final int runOrdinal,
            final int sensorId) {

        final String prefix =
                String.format(
                        Locale.ROOT,
                        "DVAS-SYSTEM|n=%d|mode=%s|"
                                + "run=%d|id=%d|",
                        scenario.n,
                        scenario.mode.csvValue,
                        runOrdinal,
                        sensorId
                );

        final byte[] prefixBytes =
                prefix.getBytes(
                        StandardCharsets.US_ASCII
                );

        if (
            prefixBytes.length
                    > REPORT_SIZE_BYTES
        ) {
            throw new IllegalStateException(
                    "Report prefix is too long."
            );
        }

        final StringBuilder report =
                new StringBuilder(
                        REPORT_SIZE_BYTES
                );

        report.append(prefix);

        final char padding =
                (char) (
                    'a' + Math.floorMod(
                            sensorId,
                            26
                    )
                );

        while (
            report.length()
                    < REPORT_SIZE_BYTES
        ) {
            report.append(padding);
        }

        final String result =
                report.toString();

        if (
            result.getBytes(
                    StandardCharsets.UTF_8
            ).length != REPORT_SIZE_BYTES
        ) {
            throw new IllegalStateException(
                    "Unexpected report byte length."
            );
        }

        return result;
    }

    private static int mapCapacity(
            final int expectedSize) {

        return Math.max(
                16,
                (int) Math.ceil(
                        expectedSize / 0.75d
                )
        );
    }

    private static void settleBetweenScenarios()
            throws InterruptedException {

        System.gc();
        Thread.sleep(100L);
    }

    private static void writeMetadata(
            final Path path,
            final Instant createdUtc,
            final Profile profile,
            final List<Scenario> scenarios,
            final int rows,
            final long setupNs)
            throws IOException {

        final Runtime runtime =
                Runtime.getRuntime();

        final List<String> lines =
                List.of(
                        "scheme=DVAS",
                        "benchmark=real-fabric-system",
                        "created_utc=" + createdUtc,
                        "profile=" + profile.name,
                        "warmup_runs="
                                + profile.warmupRuns,
                        "measurement_runs="
                                + profile.measurementRuns,
                        "report_size_bytes="
                                + REPORT_SIZE_BYTES,
                        "scenario_count="
                                + scenarios.size(),
                        "rows=" + rows,
                        "size_sweep="
                                + (
                                    profile == Profile.FULL
                                        ? "[50,100,200,400,"
                                            + "600,800,1000]"
                                        : "[2,4]"
                                ),
                        "modes=[allfix,alladm]",
                        "setup_ns_excluded="
                                + setupNs,
                        "gateway_connect_excluded=true",
                        "message_construction_excluded=true",
                        "fig9_sensor_to_en="
                                + "report+omega+id+T_i+V_i",
                        "fig9_fabric_mapping="
                                + "UTF8(Base64(U_i))+"
                                + "UTF8(Base64(Phi_i))",
                        "fig9_en_to_dv="
                                + "reports+omega+ids+"
                                + "aggregate_evidence",
                        "fig10_aggregate_evidence="
                                + "T+Z+(id+V_i+policy_byte)"
                                + "_for_each_sensor",
                        "fig11_onchain_application="
                                + "chaincode_state_key_plus_value",
                        "fig12_offchain_storage="
                                + "not_applicable",
                        "fig13_total_e2e="
                                + "sign+fabric_submit+fabric_query+"
                                + "sigverify+privacy+aggregate+"
                                + "aggverify",
                        "timing_clock=System.nanoTime",
                        "fabric_included=true",
                        "ipfs_included=false",
                        "pairing=JPBC-Type-A",
                        "pairing_r_bits=160",
                        "pairing_q_bits=512",
                        "java_version="
                                + System.getProperty(
                                        "java.version"
                                ),
                        "java_vendor="
                                + System.getProperty(
                                        "java.vendor"
                                ),
                        "os_name="
                                + System.getProperty(
                                        "os.name"
                                ),
                        "os_version="
                                + System.getProperty(
                                        "os.version"
                                ),
                        "os_arch="
                                + System.getProperty(
                                        "os.arch"
                                ),
                        "available_processors="
                                + runtime
                                    .availableProcessors(),
                        "max_jvm_memory_bytes="
                                + runtime.maxMemory(),
                        "jvm_input_arguments="
                                + ManagementFactory
                                    .getRuntimeMXBean()
                                    .getInputArguments()
                );

        Files.write(
                path,
                lines,
                StandardCharsets.UTF_8
        );
    }

    private static void writeValidation(
            final Path path,
            final Profile profile,
            final List<Scenario> scenarios,
            final int rows)
            throws IOException {

        final List<String> lines =
                List.of(
                        "validation=PASS",
                        "scheme=DVAS",
                        "profile=" + profile.name,
                        "rows=" + rows,
                        "scenarios="
                                + scenarios.size(),
                        "report_size_bytes="
                                + REPORT_SIZE_BYTES,
                        "all_correctness=true",
                        "communication_sum_check=PASS",
                        "total_e2e_sum_check=PASS",
                        "fabric_included=true",
                        "ipfs_included=false",
                        "offchain_storage=not_applicable"
                );

        Files.write(
                path,
                lines,
                StandardCharsets.UTF_8
        );
    }

    private enum Profile {
        SMOKE("smoke", 1, 2),
        FULL("full", 5, 30);

        private final String name;
        private final int warmupRuns;
        private final int measurementRuns;

        Profile(
                final String name,
                final int warmupRuns,
                final int measurementRuns) {

            this.name = name;
            this.warmupRuns = warmupRuns;
            this.measurementRuns =
                    measurementRuns;
        }

        private static Profile parse(
                final String value) {

            return switch (
                value.toLowerCase(Locale.ROOT)
            ) {
                case "smoke" -> SMOKE;
                case "full" -> FULL;
                default ->
                    throw new IllegalArgumentException(
                            "Unknown profile: "
                                    + value
                    );
            };
        }
    }

    private enum Mode {
        ALL_FIX("allfix"),
        ALL_ADM("alladm");

        private final String csvValue;

        Mode(final String csvValue) {
            this.csvValue = csvValue;
        }
    }

    private record Scenario(
            int n,
            Mode mode) {

        private Scenario {
            if (n <= 0) {
                throw new IllegalArgumentException(
                        "n must be positive."
                );
            }
        }
    }

    private record TrialResult(
            long sensorToEnBytes,
            long fabricMappingBytes,
            long enToDvBytes,
            long totalCommunicationBytes,
            long aggregateEvidenceBytes,
            long onchainApplicationBytes,
            long signNs,
            long fabricAddMappingNs,
            long fabricQueryPhiNs,
            long sigverifyNs,
            long privacyNs,
            long aggregateNs,
            long aggverifyNs,
            long totalE2eNs,
            double throughput,
            int acceptedCount,
            boolean correctness) {

        private String toCsv(
                final String profile,
                final Scenario scenario,
                final int run) {

            final int ns =
                    scenario.mode == Mode.ALL_ADM
                            ? scenario.n
                            : 0;

            return String.join(
                    ",",
                    "DVAS",
                    "system_size_sweep",
                    profile,
                    Integer.toString(run),
                    Integer.toString(
                            scenario.n
                    ),
                    Integer.toString(ns),
                    scenario.mode.csvValue,
                    Integer.toString(
                            REPORT_SIZE_BYTES
                    ),
                    Long.toString(
                            sensorToEnBytes
                    ),
                    Long.toString(
                            fabricMappingBytes
                    ),
                    Long.toString(
                            enToDvBytes
                    ),
                    Long.toString(
                            totalCommunicationBytes
                    ),
                    Long.toString(
                            aggregateEvidenceBytes
                    ),
                    Long.toString(
                            onchainApplicationBytes
                    ),
                    "",
                    "",
                    "",
                    Long.toString(signNs),
                    Long.toString(
                            fabricAddMappingNs
                    ),
                    Long.toString(
                            fabricQueryPhiNs
                    ),
                    Long.toString(sigverifyNs),
                    Long.toString(privacyNs),
                    Long.toString(aggregateNs),
                    Long.toString(aggverifyNs),
                    Long.toString(totalE2eNs),
                    formatDouble(throughput),
                    Integer.toString(
                            acceptedCount
                    ),
                    Boolean.toString(
                            correctness
                    )
            );
        }
    }

    private static String formatDouble(
            final double value) {

        return String.format(
                Locale.ROOT,
                "%.12g",
                value
        );
    }

    private record Environment(
            Setup setup,
            SensorKeyPair[] sensorKeys,
            Sign[] signers,
            SensorKeyPair edgeKey,
            SensorKeyPair dvKey,
            SanitizingStage sanitizingStage,
            Aggregate aggregate,
            AggVerify aggVerify) {

        private static Environment create(
                final int maximumN) {

            final Setup setup =
                    new Setup();

            final SensorKeyPair[] sensorKeys =
                    new SensorKeyPair[maximumN];

            final Sign[] signers =
                    new Sign[maximumN];

            for (int i = 0; i < maximumN; i++) {
                sensorKeys[i] =
                        setup.distributeKeyToSensor(i);

                signers[i] =
                        new Sign(
                                setup,
                                sensorKeys[i]
                        );
            }

            final SensorKeyPair edgeKey =
                    setup.distributeKeyToEdgeNode(
                            30_001
                    );

            final SensorKeyPair dvKey =
                    setup.distributeKeyToDVNode(
                            30_002
                    );

            return new Environment(
                    setup,
                    sensorKeys,
                    signers,
                    edgeKey,
                    dvKey,
                    new SanitizingStage(setup),
                    new Aggregate(setup),
                    new AggVerify(setup)
            );
        }
    }
}
