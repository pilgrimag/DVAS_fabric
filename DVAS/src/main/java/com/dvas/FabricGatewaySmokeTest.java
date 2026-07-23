package com.dvas;

import org.hyperledger.fabric.client.Contract;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Minimal end-to-end test for:
 *
 * Java application
 * -> Fabric Gateway
 * -> basrchannel
 * -> dvas chaincode
 * -> ledger read/write
 */
public final class FabricGatewaySmokeTest {

    private FabricGatewaySmokeTest() {
    }

    public static void main(final String[] args)
            throws Exception {

        final String suffix =
                UUID.randomUUID().toString();

        final String publicKeyBase64 =
                encode(
                        "gateway-public-key-" + suffix
                );

        final String phiBase64 =
                encode(
                        "gateway-phi-" + suffix
                );

        try (
            FabricGatewayConnection connection =
                    FabricGatewayConnection.connect()
        ) {
            final Contract contract =
                    connection.getContract();

            System.out.println(
                    "Submitting addMapping..."
            );

            final byte[] submitResponse =
                    contract.submitTransaction(
                            "addMapping",
                            publicKeyBase64,
                            phiBase64
                    );

            System.out.println(
                    "addMapping response: " +
                    new String(
                            submitResponse,
                            StandardCharsets.UTF_8
                    )
            );

            System.out.println(
                    "Evaluating queryPhi..."
            );

            final byte[] queryResponse =
                    contract.evaluateTransaction(
                            "queryPhi",
                            publicKeyBase64
                    );

            final String queriedPhi =
                    new String(
                            queryResponse,
                            StandardCharsets.UTF_8
                    );

            if (!phiBase64.equals(queriedPhi)) {
                throw new IllegalStateException(
                        "queryPhi returned an inconsistent value."
                );
            }

            System.out.println(
                    "queryPhi consistency check passed."
            );

            System.out.println(
                    "Evaluating queryAllMappings..."
            );

            final byte[] allMappingsResponse =
                    contract.evaluateTransaction(
                            "queryAllMappings"
                    );

            final String allMappings =
                    new String(
                            allMappingsResponse,
                            StandardCharsets.UTF_8
                    );

            System.out.println(
                        "queryAllMappings response: " +
                        allMappings
                    );

            final JsonElement parsedResponse =
                        JsonParser.parseString(allMappings);

            if (!parsedResponse.isJsonArray()) {
                    throw new IllegalStateException(
                        "queryAllMappings did not return a JSON array."
                    );
                }

            final JsonArray mappings =
                    parsedResponse.getAsJsonArray();

            boolean mappingFound = false;

            for (JsonElement element : mappings) {
                if (!element.isJsonObject()) {
                    continue;
                }

                final JsonObject mapping =
                    element.getAsJsonObject();

                if (
                    !mapping.has("publicKey") ||
                    !mapping.has("phi")
                ) {
                    continue;
                }

                final String returnedPublicKey =
                    mapping.get("publicKey").getAsString();

                final String returnedPhi =
                    mapping.get("phi").getAsString();

                if (
                    publicKeyBase64.equals(returnedPublicKey) &&
                    phiBase64.equals(returnedPhi)
                ) {
                    mappingFound = true;
                    break;
                }
            }

if (!mappingFound) {
    throw new IllegalStateException(
            "queryAllMappings did not contain " +
            "the submitted mapping."
    );
}

System.out.println(
        "queryAllMappings consistency check passed."
);

            System.out.println();
            System.out.println(
                    "DVAS Fabric Gateway smoke test passed."
            );
        }
    }

    private static String encode(
            final String value
    ) {
        return Base64.getEncoder()
                .encodeToString(
                        value.getBytes(
                                StandardCharsets.UTF_8
                        )
                );
    }
}
