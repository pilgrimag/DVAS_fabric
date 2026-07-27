package com.dvas;

import com.dvas.Aggregate.AggregateResult;
import com.dvas.Sign.Signature;
import com.dvas.sendToEN.Send;
import it.unisa.dia.gas.jpbc.Element;

import java.io.BufferedWriter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reproducible pure-cryptography benchmark for DVAS.
 *
 * <p>The benchmark deliberately excludes Fabric, IPFS, setup,
 * key distribution, message construction, and CSV I/O from all
 * measured cryptographic stages.</p>
 */
public final class DvasCryptoBenchmarkMain {

    private static final String CSV_NAME =
            "dvas-crypto-raw.csv";

    private static final String METADATA_NAME =
            "dvas-crypto-metadata.txt";

    private static final String VALIDATION_NAME =
            "VALIDATION";

    private static final int REPORT_SIZE_BYTES = 1024;

    private static final int[] FULL_SIZE_SWEEP = {
        50, 100, 200, 400, 600, 800, 1000
    };

    private static final int[] FULL_SENSITIVE_SWEEP = {
        10, 30, 70, 120, 170, 190
    };

    private static final String CSV_HEADER =
            "scheme,experiment,profile,run,n,ns,nr,"
                    + "report_size_bytes,sign_ns,"
                    + "kem_encap_ns,aead_encrypt_ns,"
                    + "privacy_ns,sigverify_ns,"
                    + "aggregate_ns,aggverify_ns,"
                    + "total_crypto_ns,kem_decap_ns,"
                    + "aead_decrypt_ns,recovery_ns,"
                    + "accepted_count,correctness";

    private DvasCryptoBenchmarkMain() {
    }

    public static void main(
            final String[] args) throws Exception {

        if (args.length != 2) {
            throw new IllegalArgumentException(
                    "Usage: DvasCryptoBenchmarkMain "
                            + "<output-directory> "
                            + "<smoke|full>"
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

        final Instant createdUtc = Instant.now();
        final List<Scenario> scenarios =
                scenariosFor(profile);

        final int maximumN =
                scenarios.stream()
                        .mapToInt(Scenario::n)
                        .max()
                        .orElseThrow();

        System.out.printf(
                Locale.ROOT,
                "DVAS pure-crypto benchmark: "
                        + "profile=%s, scenarios=%d, "
                        + "warmups=%d, measurements=%d, "
                        + "maxN=%d%n",
                profile.name,
                scenarios.size(),
                profile.warmupRuns,
                profile.measurementRuns,
                maximumN
        );

        final Environment environment =
                Environment.create(maximumN);

        final Path csvPath =
                outputDirectory.resolve(CSV_NAME);

        int writtenRows = 0;

        try (
            BufferedWriter writer =
                    Files.newBufferedWriter(
                            csvPath,
                            StandardCharsets.UTF_8
                    )
        ) {
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
                        "[%d/%d] experiment=%s, "
                                + "n=%d, ns=%d%n",
                        scenarioIndex + 1,
                        scenarios.size(),
                        scenario.experiment,
                        scenario.n,
                        scenario.ns
                );

                settleBetweenScenarios();

                for (
                    int warmup = 1;
                    warmup <= profile.warmupRuns;
                    warmup++
                ) {
                    executeTrial(
                            environment,
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
                    writtenRows++;
                }

                writer.flush();
            }
        }

        final int expectedRows =
                Math.multiplyExact(
                        scenarios.size(),
                        profile.measurementRuns
                );

        if (writtenRows != expectedRows) {
            throw new IllegalStateException(
                    "Unexpected CSV row count: "
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
                writtenRows
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
                "DVAS pure-crypto benchmark: PASS"
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
                "fabric_included=false"
        );
        System.out.println(
                "ipfs_included=false"
        );
    }

    private static TrialResult executeTrial(
            final Environment environment,
            final Scenario scenario,
            final int runOrdinal) {

        final int n = scenario.n;
        final int ns = scenario.ns;

        final List<Integer> adm =
                integerRange(0, ns);

        final List<Integer> fix =
                integerRange(ns, n);

        final List<Integer> index =
                integerRange(0, n);

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

        final List<Element> vList =
                new ArrayList<>(n);

        final List<Element> uiList =
                new ArrayList<>(n);

        final Map<Integer, Element> uiMap =
                new HashMap<>(mapCapacity(n));

        for (int i = 0; i < n; i++) {
            sensorIds[i] = i;

            final String report =
                    createAsciiReport(
                            scenario,
                            runOrdinal,
                            i
                    );

            messages.add(
                    new Message(
                            report,
                            "DVAS-POLICY-V1"
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

        final SanitizingStage sanitizingStage =
                environment.sanitizingStage;

        final long verifyStart =
                System.nanoTime();

        int acceptedCount = 0;

        for (int i = 0; i < n; i++) {
            final boolean accepted =
                    sanitizingStage
                            .verifyOriginalSignatureOffChain(
                                    uiList.get(i),
                                    messages.get(i),
                                    signatures.get(i),
                                    environment.setup
                                            .getP(),
                                    signatures.get(i)
                                            .getPhi_i()
                            );

            if (!accepted) {
                throw new IllegalStateException(
                        "Original signature rejected: "
                                + "sensor=" + i
                                + ", n=" + n
                                + ", ns=" + ns
                );
            }

            acceptedCount++;
        }

        final long sigverifyNs =
                System.nanoTime() - verifyStart;

        long privacyNs = 0;

        if (ns > 0) {
            final long privacyStart =
                    System.nanoTime();

            for (int i = 0; i < ns; i++) {
                sanitizingStage
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
                originalMessages,
                messages,
                ns
        );

        final Aggregate aggregate =
                environment.aggregate;

        final List<Send> sends =
                List.of();

        final long aggregateStart =
                System.nanoTime();

        final AggregateResult aggregateResult =
                aggregate.computeAggregate(
                        environment.setup,
                        environment.setup.getP(),
                        environment.dvKey.getU_i(),
                        signatures,
                        sensorIds,
                        adm,
                        fix,
                        new HashMap<>(),
                        sends,
                        index
                );

        final long aggregateNs =
                System.nanoTime()
                        - aggregateStart;

        if (
            aggregateResult == null
                    || aggregateResult.getT()
                            == null
                    || aggregateResult.getZ()
                            == null
        ) {
            throw new IllegalStateException(
                    "Aggregate generation failed."
            );
        }

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
                                sends
                        );

        final long aggverifyNs =
                System.nanoTime()
                        - aggverifyStart;

        if (!aggregateAccepted) {
            throw new IllegalStateException(
                    "Aggregate signature rejected: "
                            + "n=" + n
                            + ", ns=" + ns
            );
        }

        final long totalCryptoNs =
                Math.addExact(
                        Math.addExact(
                                signNs,
                                sigverifyNs
                        ),
                        Math.addExact(
                                Math.addExact(
                                        privacyNs,
                                        aggregateNs
                                ),
                                aggverifyNs
                        )
                );

        return new TrialResult(
                signNs,
                privacyNs,
                sigverifyNs,
                aggregateNs,
                aggverifyNs,
                totalCryptoNs,
                acceptedCount,
                aggregateAccepted
        );
    }

    private static void validateTrial(
            final Scenario scenario,
            final TrialResult result) {

        if (result.signNs <= 0) {
            throw new IllegalStateException(
                    "sign_ns must be positive"
            );
        }

        if (result.sigverifyNs <= 0) {
            throw new IllegalStateException(
                    "sigverify_ns must be positive"
            );
        }

        if (result.aggregateNs <= 0) {
            throw new IllegalStateException(
                    "aggregate_ns must be positive"
            );
        }

        if (result.aggverifyNs <= 0) {
            throw new IllegalStateException(
                    "aggverify_ns must be positive"
            );
        }

        if (
            scenario.ns == 0
                    && result.privacyNs != 0
        ) {
            throw new IllegalStateException(
                    "privacy_ns must be zero "
                            + "when ns=0"
            );
        }

        if (
            scenario.ns > 0
                    && result.privacyNs <= 0
        ) {
            throw new IllegalStateException(
                    "privacy_ns must be positive "
                            + "when ns>0"
            );
        }

        if (
            result.acceptedCount
                    != scenario.n
        ) {
            throw new IllegalStateException(
                    "Unexpected accepted_count"
            );
        }

        if (!result.correctness) {
            throw new IllegalStateException(
                    "Correctness must be true"
            );
        }

        final long recomputedTotal =
                Math.addExact(
                        Math.addExact(
                                result.signNs,
                                result.sigverifyNs
                        ),
                        Math.addExact(
                                Math.addExact(
                                        result.privacyNs,
                                        result.aggregateNs
                                ),
                                result.aggverifyNs
                        )
                );

        if (
            recomputedTotal
                    != result.totalCryptoNs
        ) {
            throw new IllegalStateException(
                    "total_crypto_ns mismatch"
            );
        }
    }

    private static void validateSanitization(
            final List<String> originals,
            final List<Message> messages,
            final int ns) {

        for (
            int i = 0;
            i < messages.size();
            i++
        ) {
            final String original =
                    originals.get(i);

            final String current =
                    messages.get(i).getM();

            if (i < ns) {
                if (current.equals(original)) {
                    throw new IllegalStateException(
                            "ADM message was not "
                                    + "sanitized: "
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

    private static List<Scenario> scenariosFor(
            final Profile profile) {

        final List<Scenario> scenarios =
                new ArrayList<>();

        if (profile == Profile.FULL) {
            for (int n : FULL_SIZE_SWEEP) {
                scenarios.add(
                        new Scenario(
                                "size_sweep",
                                n,
                                0
                        )
                );
            }

            for (
                int ns :
                FULL_SENSITIVE_SWEEP
            ) {
                scenarios.add(
                        new Scenario(
                                "sensitive_sweep",
                                200,
                                ns
                        )
                );
            }
        } else {
            scenarios.add(
                    new Scenario(
                            "size_sweep",
                            2,
                            0
                    )
            );

            scenarios.add(
                    new Scenario(
                            "size_sweep",
                            4,
                            0
                    )
            );

            scenarios.add(
                    new Scenario(
                            "sensitive_sweep",
                            4,
                            1
                    )
            );

            scenarios.add(
                    new Scenario(
                            "sensitive_sweep",
                            4,
                            3
                    )
            );
        }

        return List.copyOf(scenarios);
    }

    private static List<Integer> integerRange(
            final int fromInclusive,
            final int toExclusive) {

        final List<Integer> values =
                new ArrayList<>(
                        Math.max(
                                0,
                                toExclusive
                                        - fromInclusive
                        )
                );

        for (
            int value = fromInclusive;
            value < toExclusive;
            value++
        ) {
            values.add(value);
        }

        return values;
    }

    private static String createAsciiReport(
            final Scenario scenario,
            final int runOrdinal,
            final int sensorId) {

        final String prefix =
                String.format(
                        Locale.ROOT,
                        "DVAS|%s|n=%d|ns=%d|"
                                + "run=%d|id=%d|",
                        scenario.experiment,
                        scenario.n,
                        scenario.ns,
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
                    "Report prefix exceeds "
                            + REPORT_SIZE_BYTES
                            + " bytes"
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

        final int encodedLength =
                result.getBytes(
                        StandardCharsets.UTF_8
                ).length;

        if (
            encodedLength
                    != REPORT_SIZE_BYTES
        ) {
            throw new IllegalStateException(
                    "Unexpected report byte length: "
                            + encodedLength
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
            final int writtenRows)
            throws IOException {

        final Runtime runtime =
                Runtime.getRuntime();

        final List<String> lines =
                List.of(
                        "scheme=DVAS",
                        "benchmark=pure-cryptography",
                        "created_utc="
                                + createdUtc,
                        "profile="
                                + profile.name,
                        "warmup_runs="
                                + profile.warmupRuns,
                        "measurement_runs="
                                + profile.measurementRuns,
                        "report_size_bytes="
                                + REPORT_SIZE_BYTES,
                        "pairing=JPBC-Type-A",
                        "pairing_r_bits=160",
                        "pairing_q_bits=512",
                        "masking_rule=DVAS_MASK_V1",
                        "hash=SHA-256",
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
                                    .getInputArguments(),
                        "scenario_count="
                                + scenarios.size(),
                        "rows="
                                + writtenRows,
                        "size_sweep="
                                + sizeSweepDescription(
                                        profile
                                ),
                        "fixed_n="
                                + (
                                    profile
                                            == Profile.FULL
                                        ? 200
                                        : 4
                                ),
                        "sensitive_sweep="
                                + sensitiveSweepDescription(
                                        profile
                                ),
                        "timing_clock=System.nanoTime",
                        "fig1_sign="
                                + "cumulative_signature_ns",
                        "fig2_sigverify="
                                + "cumulative_original_"
                                + "signature_verification_ns",
                        "fig3_aggregate="
                                + "preverified_aggregation_ns",
                        "fig4_aggverify="
                                + "designated_aggregate_"
                                + "verification_ns",
                        "fig5_privacy="
                                + "verified_ADM_"
                                + "sanitization_ns",
                        "fig6_processing_and_signing="
                                + "privacy_ns_plus_sign_ns",
                        "fig7_total_crypto="
                                + "sign_plus_sigverify_plus_"
                                + "privacy_plus_aggregate_plus_"
                                + "aggverify",
                        "fig8_recovery=not_applicable",
                        "fabric_included=false",
                        "ipfs_included=false",
                        "setup_included=false",
                        "key_distribution_included=false",
                        "message_construction_included=false",
                        "csv_io_included=false"
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
            final int writtenRows)
            throws IOException {

        final List<String> lines =
                List.of(
                        "validation=PASS",
                        "scheme=DVAS",
                        "profile="
                                + profile.name,
                        "rows="
                                + writtenRows,
                        "scenarios="
                                + scenarios.size(),
                        "report_size_bytes="
                                + REPORT_SIZE_BYTES,
                        "all_correctness=true",
                        "total_crypto_sum_check=PASS",
                        "fabric_included=false",
                        "ipfs_included=false"
                );

        Files.write(
                path,
                lines,
                StandardCharsets.UTF_8
        );
    }

    private static String sizeSweepDescription(
            final Profile profile) {

        if (profile == Profile.FULL) {
            return "[50, 100, 200, 400, "
                    + "600, 800, 1000]";
        }

        return "[2, 4]";
    }

    private static String sensitiveSweepDescription(
            final Profile profile) {

        if (profile == Profile.FULL) {
            return "[10, 30, 70, 120, "
                    + "170, 190]";
        }

        return "[1, 3]";
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

    private record Scenario(
            String experiment,
            int n,
            int ns) {

        private Scenario {
            if (
                !"size_sweep".equals(
                        experiment
                )
                        && !"sensitive_sweep"
                            .equals(
                                    experiment
                            )
            ) {
                throw new IllegalArgumentException(
                        "Unknown experiment: "
                                + experiment
                );
            }

            if (n <= 0) {
                throw new IllegalArgumentException(
                        "n must be positive"
                );
            }

            if (ns < 0 || ns > n) {
                throw new IllegalArgumentException(
                        "ns must satisfy 0 <= ns <= n"
                );
            }
        }
    }

    private record TrialResult(
            long signNs,
            long privacyNs,
            long sigverifyNs,
            long aggregateNs,
            long aggverifyNs,
            long totalCryptoNs,
            int acceptedCount,
            boolean correctness) {

        private String toCsv(
                final String profile,
                final Scenario scenario,
                final int run) {

            return String.join(
                    ",",
                    "DVAS",
                    scenario.experiment,
                    profile,
                    Integer.toString(run),
                    Integer.toString(
                            scenario.n
                    ),
                    Integer.toString(
                            scenario.ns
                    ),
                    "",
                    Integer.toString(
                            REPORT_SIZE_BYTES
                    ),
                    Long.toString(signNs),
                    "",
                    "",
                    Long.toString(privacyNs),
                    Long.toString(sigverifyNs),
                    Long.toString(aggregateNs),
                    Long.toString(aggverifyNs),
                    Long.toString(totalCryptoNs),
                    "",
                    "",
                    "",
                    Integer.toString(
                            acceptedCount
                    ),
                    Boolean.toString(
                            correctness
                    )
            );
        }
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
                        setup.distributeKeyToSensor(
                                i
                        );

                signers[i] =
                        new Sign(
                                setup,
                                sensorKeys[i]
                        );
            }

            final SensorKeyPair edgeKey =
                    setup.distributeKeyToEdgeNode(
                            20_001
                    );

            final SensorKeyPair dvKey =
                    setup.distributeKeyToDVNode(
                            20_002
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
