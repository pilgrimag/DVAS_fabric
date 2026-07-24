package com.dvas;

import it.unisa.dia.gas.jpbc.Element;

import org.hyperledger.fabric.client.Contract;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Single-round diagnostic test for the DVAS implementation.
 *
 * Modes:
 *   positive : two ADM sensors; positive path and aggregate tamper test
 *   mixed    : one ADM sensor and one FIX sensor; includes FIX tamper test
 */
public final class DvasSingleRunCorrectnessTest {

    private DvasSingleRunCorrectnessTest() {
    }

    public static void main(final String[] args)
            throws Exception {

        final String mode =
                args.length == 0
                        ? "positive"
                        : args[0].trim()
                                .toLowerCase(Locale.ROOT);

        final int totalSensors = 2;
        final int sensitiveSensors;

        switch (mode) {
            case "positive", "alladm" ->
                    sensitiveSensors = 2;

            case "mixed" ->
                    sensitiveSensors = 1;

            case "allfix" ->
                    sensitiveSensors = 0;

            default -> throw new IllegalArgumentException(
                    "Mode must be positive, alladm, mixed, or allfix."
            );
        }

        System.out.printf(
                "DVAS single-round test: mode=%s, total=%d, ADM=%d%n",
                mode,
                totalSensors,
                sensitiveSensors
        );

        try (
            FabricGatewayConnection connection =
                    FabricGatewayConnection.connect()
        ) {
            runScenario(
                    connection.getContract(),
                    totalSensors,
                    sensitiveSensors,
                    mode
            );
        }

        System.out.println();
        System.out.println(
                "DVAS single-round correctness test passed."
        );
    }

    private static void runScenario(
            final Contract contract,
            final int totalSensors,
            final int sensitiveSensors,
            final String mode
    ) throws Exception {

        /*
         * 1. Setup
         */
        System.out.println("[1/7] Setup");

        final Setup setup =
                new Setup();

        require(
                setup.getPairing() != null,
                "Pairing was not initialized."
        );

        require(
                setup.getP() != null,
                "Generator P was not initialized."
        );

        final int[] sensorIds =
                new int[totalSensors];

        final SensorKeyPair[] sensorKeys =
                new SensorKeyPair[totalSensors];

        for (int i = 0; i < totalSensors; i++) {
            sensorIds[i] = i;

            sensorKeys[i] =
                    setup.distributeKeyToSensor(i);

            require(
                    sensorKeys[i] != null,
                    "Sensor key generation failed for ID " + i
            );

            require(
                    setup.verifySensorKey(
                            i,
                            sensorKeys[i]
                    ),
                    "Sensor key equation failed for ID " + i
            );
        }

        final SensorKeyPair edgeNodeKey =
                setup.distributeKeyToEdgeNode(11);

        final SensorKeyPair dvNodeKey =
                setup.distributeKeyToDVNode(111);

        System.out.println(
                "  PASS: system and entity keys generated."
        );

        /*
         * 2. Join and grouping
         */
        System.out.println("[2/7] Join");

        final Join join =
                new Join(setup);

        final List<Integer> adm =
                new ArrayList<>();

        final List<Integer> fix =
                new ArrayList<>();

        final List<Integer> index =
                new ArrayList<>();

        for (int i = 0; i < totalSensors; i++) {
            /*
             * authenticateSensor() currently names its third
             * argument u_i, but internally compares it with the
             * public point U_i. Therefore getU_i() is required.
             */
            final boolean authenticated =
                    join.authenticateSensor(
                            i,
                            sensorKeys[i].getR_i(),
                            sensorKeys[i].getU_i()
                    );

            require(
                    authenticated,
                    "Join authentication failed for ID " + i
            );

            final boolean sensitive =
                    i < sensitiveSensors;

            join.groupTask(
                    i,
                    sensitive,
                    adm,
                    fix
            );

            index.add(i);
        }

        require(
                adm.size() == sensitiveSensors,
                "Unexpected ADM size: " + adm
        );

        require(
                fix.size() ==
                        totalSensors - sensitiveSensors,
                "Unexpected FIX size: " + fix
        );

        for (Integer id : adm) {
            require(
                    !fix.contains(id),
                    "Sensor occurs in both ADM and FIX: " + id
            );
        }

        System.out.println("  ADM = " + adm);
        System.out.println("  FIX = " + fix);
        System.out.println(
                "  PASS: authentication and grouping completed."
        );

        /*
         * 3. Sign
         */
        System.out.println("[3/7] Sign");

        final List<Message> messages =
                new ArrayList<>();

        final List<Sign.Signature> signatures =
                new ArrayList<>();

        final List<Element> originalT =
                new ArrayList<>();

        final List<Element> originalV =
                new ArrayList<>();

        final List<Element> originalPhi =
                new ArrayList<>();

        for (int i = 0; i < totalSensors; i++) {
            final Message message =
                    new Message(
                            "single-run-message-" + i,
                            "single-run-policy"
                    );

            messages.add(message);

            final Sign signer =
                    new Sign(
                            setup,
                            sensorKeys[i]
                    );

            final Sign.Signature signature =
                    signer.generateSignature(
                            message,
                            message.getOmega(),
                            sensorIds[i],
                            edgeNodeKey.getU_i(),
                            dvNodeKey.getU_i()
                    );

            require(
                    signature != null,
                    "Signature generation returned null."
            );

            require(
                    signature.getId() == i,
                    "Signature ID mismatch for sensor " + i
            );

            signatures.add(signature);

            originalT.add(
                    signature.getT_i()
                            .duplicate()
                            .getImmutable()
            );

            originalV.add(
                    signature.getV_i()
                            .duplicate()
                            .getImmutable()
            );

            originalPhi.add(
                    signature.getPhi_i()
                            .duplicate()
                            .getImmutable()
            );
        }

        System.out.println(
                "  PASS: individual signatures generated."
        );

        /*
         * 4. Fabric mapping round trip
         */
        System.out.println("[4/7] Fabric mapping");

        final Blockchain blockchain =
                new Blockchain(
                        contract,
                        setup.getPairing()
                );

        for (int i = 0; i < totalSensors; i++) {
            final String publicKeyBase64 =
                    blockchain.elementToBase64String(
                            sensorKeys[i].getU_i()
                    );

            final String phiBase64 =
                    blockchain.elementToBase64String(
                            signatures.get(i).getPhi_i()
                    );

            blockchain.addMapping(
                    publicKeyBase64,
                    phiBase64
            );

            final Element queriedPhi =
                    blockchain.getPhiByPublicKey(
                            sensorKeys[i].getU_i()
                    );

            require(
                    queriedPhi != null,
                    "Fabric returned null Phi for sensor " + i
            );

            require(
                    queriedPhi.isEqual(
                            signatures.get(i).getPhi_i()
                    ),
                    "Fabric Phi round-trip mismatch for sensor " + i
            );
        }

        System.out.println(
                "  PASS: every U_i -> Phi_i mapping round-tripped."
        );

        /*
         * Prepare public-key collections before sanitization.
         */
        final List<Element> uiList =
                new ArrayList<>();

        final Map<Integer, Element> uiMap =
                new HashMap<>();

        for (int i = 0; i < totalSensors; i++) {
            final Element publicKey =
                    sensorKeys[i].getU_i()
                            .duplicate()
                            .getImmutable();

            uiList.add(publicKey);
            uiMap.put(i, publicKey);
        }

        /*
         * 5. Sanitizing
         */
        System.out.println("[5/7] Sanitizing");

        final SanitizingStage sanitizer =
                new SanitizingStage(setup);

        for (int i = 0; i < totalSensors; i++) {
            final SanitizingStage.SanitizingSubTimings result =
                    sanitizer.verifySignature(
                            setup,
                            uiMap.get(i),
                            uiList,
                            edgeNodeKey.getu_i(),
                            messages.get(i),
                            signatures.get(i),
                            setup.getP(),
                            dvNodeKey.getU_i(),
                            blockchain,
                            adm
                    );

            require(
                    result.result,
                    "Signature verification failed during " +
                    "sanitization for sensor " + i
            );

            if (adm.contains(i)) {
                require(
                        !signatures.get(i)
                                .getV_i()
                                .isEqual(originalV.get(i)),
                        "ADM signature V_i was not randomized " +
                        "for sensor " + i
                );
            } else {
                require(
                        signatures.get(i)
                                .getT_i()
                                .isEqual(originalT.get(i)),
                        "FIX signature T_i was unexpectedly changed."
                );

                require(
                        signatures.get(i)
                                .getV_i()
                                .isEqual(originalV.get(i)),
                        "FIX signature V_i was unexpectedly changed."
                );

                require(
                        signatures.get(i)
                                .getPhi_i()
                                .isEqual(originalPhi.get(i)),
                        "FIX signature Phi_i was unexpectedly changed."
                );
            }
        }

        System.out.println(
                "  PASS: all original signatures verified."
        );

        /*
         * Current fmod() returns its input unchanged. This is
         * reported rather than treated as successful sanitization.
         */
        System.out.println(
                "  NOTE: fmod currently leaves message content unchanged."
        );

        /*
         * 6. Aggregate
         */
        System.out.println("[6/7] Aggregate");

        final Aggregate aggregate =
                new Aggregate(setup);

        final Aggregate.AggregateResult aggregateResult =
                aggregate.computeAggregate(
                        setup,
                        setup.getP(),
                        dvNodeKey.getU_i(),
                        signatures,
                        sensorIds,
                        adm,
                        fix,
                        new HashMap<>(),
                        new ArrayList<>(),
                        index
                );

        require(
                aggregateResult != null,
                "Aggregate result is null."
        );

        require(
                aggregateResult.getT() != null,
                "Aggregate T is null."
        );

        require(
                aggregateResult.getZ() != null,
                "Aggregate Z is null."
        );

        System.out.println(
                "  PASS: aggregate object generated."
        );

        /*
         * 7. Aggregate verification
         */
        System.out.println("[7/7] Aggregate verification");

        final AggVerify aggregateVerifier =
                new AggVerify(setup);

        final boolean valid =
                aggregateVerifier.verifyAggregate(
                        setup,
                        aggregateResult.getT(),
                        setup.getP(),
                        edgeNodeKey.getU_i(),
                        dvNodeKey.getu_i(),
                        aggregateResult.getZ(),
                        fix,
                        adm,
                        messages,
                        uiMap,
                        aggregateResult,
                        originalPhi,
                        totalSensors,
                        index,
                        uiList,
                        originalV,
                        new ArrayList<>()
                );

        require(
                valid,
                "Valid aggregate signature was rejected."
        );

        System.out.println(
                "  PASS: valid aggregate signature accepted."
        );

        // if ("positive".equals(mode)) {
            /*
             * The aggregate must reject a modified T value.
             */
        final Element tamperedT =
                aggregateResult.getT()
                        .duplicate()
                        .add(setup.getP())
                        .getImmutable();

        final boolean tamperedAccepted =
                aggregateVerifier.verifyAggregate(
                        setup,
                        tamperedT,
                        setup.getP(),
                        edgeNodeKey.getU_i(),
                        dvNodeKey.getu_i(),
                        aggregateResult.getZ(),
                        fix,
                        adm,
                        messages,
                        uiMap,
                        aggregateResult,
                        originalPhi,
                        totalSensors,
                        index,
                        uiList,
                        originalV,
                        new ArrayList<>()
                );

        require(
                !tamperedAccepted,
                "Tampered aggregate T was accepted."
        );

        System.out.println(
                "  PASS: modified aggregate T rejected."
        );
        // }

        if (!fix.isEmpty()) {
            /*
             * A correct mixed-set aggregate must bind FIX messages.
             */
            final int fixId =
                    fix.get(0);

            final String originalMessage =
                    messages.get(fixId).getM();

            messages.get(fixId).setM(
                    originalMessage + "-tampered"
            );

            final boolean fixTamperAccepted =
                    aggregateVerifier.verifyAggregate(
                            setup,
                            aggregateResult.getT(),
                            setup.getP(),
                            edgeNodeKey.getU_i(),
                            dvNodeKey.getu_i(),
                            aggregateResult.getZ(),
                            fix,
                            adm,
                            messages,
                            uiMap,
                            aggregateResult,
                            originalPhi,
                            totalSensors,
                            index,
                            uiList,
                            originalV,
                            new ArrayList<>()
                    );

            messages.get(fixId).setM(
                    originalMessage
            );

            require(
                    !fixTamperAccepted,
                    "FIX-message tampering was accepted. " +
                    "The aggregate is not binding the FIX subset."
            );

            System.out.println(
                    "  PASS: modified FIX message rejected."
            );
        }

        if (!adm.isEmpty()) {
            final int admId =
                    adm.get(0);

            final String originalMessage =
                    messages.get(admId).getM();

            messages.get(admId).setM(
                    originalMessage + "-tampered"
            );

            final boolean admTamperAccepted =
                    aggregateVerifier.verifyAggregate(
                            setup,
                            aggregateResult.getT(),
                            setup.getP(),
                            edgeNodeKey.getU_i(),
                            dvNodeKey.getu_i(),
                            aggregateResult.getZ(),
                            fix,
                            adm,
                            messages,
                            uiMap,
                            aggregateResult,
                            originalPhi,
                            totalSensors,
                            index,
                            uiList,
                            originalV,
                            new ArrayList<>()
                    );

            messages.get(admId).setM(
                    originalMessage
            );

            require(
                    !admTamperAccepted,
                    "ADM-message tampering was accepted."
            );

            System.out.println(
                    "  PASS: modified ADM message rejected."
            );
        }
    }

    private static void require(
            final boolean condition,
            final String errorMessage
    ) {
        if (!condition) {
            throw new IllegalStateException(
                    errorMessage
            );
        }
    }
}