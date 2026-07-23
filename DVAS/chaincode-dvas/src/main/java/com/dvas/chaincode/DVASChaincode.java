package com.dvas.chaincode;

import com.google.gson.Gson;
import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ResponseUtils;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DVASChaincode extends ChaincodeBase {

    private static final Gson GSON = new Gson();

    @Override
    public Response init(final ChaincodeStub stub) {
        return ResponseUtils.newSuccessResponse("Init Success!");
    }

    @Override
    public Response invoke(final ChaincodeStub stub) {
        final String function = stub.getFunction();
        final List<String> args = stub.getParameters();

        try {
            return switch (function) {
                case "InitLedger" ->
                    ResponseUtils.newSuccessResponse(
                        "InitLedger function called."
                    );

                case "addMapping" -> invokeAddMapping(stub, args);

                case "queryPhi" -> invokeQueryPhi(stub, args);

                case "queryAllMappings" ->
                    invokeQueryAllMappings(stub, args);

                default ->
                    ResponseUtils.newErrorResponse(
                        "Invalid chaincode function name: " + function
                    );
            };
        } catch (RuntimeException exception) {
            return ResponseUtils.newErrorResponse(
                "Error during chaincode invocation: " +
                exception.getMessage()
            );
        }
    }

    private Response invokeAddMapping(
        final ChaincodeStub stub,
        final List<String> args
    ) {
        if (args.size() != 2) {
            return ResponseUtils.newErrorResponse(
                "addMapping expects 2 arguments: " +
                "[publicKeyBase64, phiBase64]."
            );
        }

        final String result = addMapping(
            stub,
            args.get(0),
            args.get(1)
        );

        return ResponseUtils.newSuccessResponse(result);
    }

    private Response invokeQueryPhi(
        final ChaincodeStub stub,
        final List<String> args
    ) {
        if (args.size() != 1) {
            return ResponseUtils.newErrorResponse(
                "queryPhi expects 1 argument: [publicKeyBase64]."
            );
        }

        final String phi = queryPhi(stub, args.get(0));

        if (phi == null) {
            return ResponseUtils.newErrorResponse(
                "Phi_i not found for the supplied public key."
            );
        }

        return ResponseUtils.newSuccessResponse(
            phi.getBytes(StandardCharsets.UTF_8)
        );
    }

    private Response invokeQueryAllMappings(
        final ChaincodeStub stub,
        final List<String> args
    ) {
        if (!args.isEmpty()) {
            return ResponseUtils.newErrorResponse(
                "queryAllMappings expects no arguments."
            );
        }

        final String result = queryAllMappings(stub);

        return ResponseUtils.newSuccessResponse(
            result.getBytes(StandardCharsets.UTF_8)
        );
    }

    public String addMapping(
        final ChaincodeStub stub,
        final String publicKeyBase64,
        final String phiBase64
    ) {
        requireNonBlank(publicKeyBase64, "Public key");
        requireNonBlank(phiBase64, "Phi_i");

        stub.putStringState(publicKeyBase64, phiBase64);

        return "Mapping added successfully.";
    }

    public String queryPhi(
        final ChaincodeStub stub,
        final String publicKeyBase64
    ) {
        requireNonBlank(publicKeyBase64, "Public key");

        final String value = stub.getStringState(publicKeyBase64);

        return value == null || value.isBlank() ? null : value;
    }

    public String queryAllMappings(final ChaincodeStub stub) {
        final List<Map<String, String>> mappings =
            new ArrayList<>();

        try (
            QueryResultsIterator<KeyValue> results =
                stub.getStateByRange("", "")
        ) {
            for (KeyValue keyValue : results) {
                final Map<String, String> mapping =
                    new LinkedHashMap<>();

                mapping.put("publicKey", keyValue.getKey());
                mapping.put(
                    "phi",
                    new String(
                        keyValue.getValue(),
                        StandardCharsets.UTF_8
                    )
                );

                mappings.add(mapping);
            }
        }

        return GSON.toJson(mappings);
    }

    private static void requireNonBlank(
        final String value,
        final String fieldName
    ) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                fieldName + " cannot be empty."
            );
        }
    }

    public static void main(final String[] args) {
        new DVASChaincode().start(args);
    }
}