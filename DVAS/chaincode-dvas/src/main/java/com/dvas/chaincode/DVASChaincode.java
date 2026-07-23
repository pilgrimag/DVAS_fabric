package com.dvas.chaincode;

import com.google.gson.Gson;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.Contract;
import org.hyperledger.fabric.contract.annotation.Default;
import org.hyperledger.fabric.contract.annotation.Info;
import org.hyperledger.fabric.contract.annotation.Transaction;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DVAS ledger contract.
 *
 * Stores the mapping:
 *
 *     publicKeyBase64 -> phiBase64
 *
 * Cryptographic pairing operations remain outside the chaincode.
 */
@Contract(
    name = "dvas",
    info = @Info(
        title = "DVAS Mapping Contract",
        description =
            "Stores DVAS public-key-to-phi mappings.",
        version = "1.1.0"
    )
)
@Default
public final class DVASChaincode
        implements ContractInterface {

    private static final Gson GSON =
        new Gson();

    /**
     * No application state needs to be initialized.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String InitLedger(final Context context) {
        return "DVAS ledger initialized.";
    }

    /**
     * Adds or replaces one public-key-to-phi mapping.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String addMapping(
        final Context context,
        final String publicKeyBase64,
        final String phiBase64
    ) {
        requireNonBlank(
            publicKeyBase64,
            "Public key"
        );

        requireNonBlank(
            phiBase64,
            "Phi_i"
        );

        context.getStub().putStringState(
            publicKeyBase64,
            phiBase64
        );

        return "Mapping added successfully.";
    }

    /**
     * Returns the phi value associated with a public key.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryPhi(
        final Context context,
        final String publicKeyBase64
    ) {
        requireNonBlank(
            publicKeyBase64,
            "Public key"
        );

        final String phiBase64 =
            context.getStub().getStringState(
                publicKeyBase64
            );

        if (
            phiBase64 == null ||
            phiBase64.isBlank()
        ) {
            throw new ChaincodeException(
                "Phi_i not found for the supplied public key."
            );
        }

        return phiBase64;
    }

    /**
     * Returns every mapping as a JSON array.
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryAllMappings(
        final Context context
    ) {
        final ChaincodeStub stub =
            context.getStub();

        final List<Map<String, String>> mappings =
            new ArrayList<>();

        try (
            QueryResultsIterator<KeyValue> results =
                stub.getStateByRange("", "")
        ) {
            for (KeyValue keyValue : results) {
                final Map<String, String> mapping =
                    new LinkedHashMap<>();

                mapping.put(
                    "publicKey",
                    keyValue.getKey()
                );

                mapping.put(
                    "phi",
                    keyValue.getStringValue()
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
        if (
            value == null ||
            value.isBlank()
        ) {
            throw new ChaincodeException(
                fieldName + " cannot be empty."
            );
        }
    }
}