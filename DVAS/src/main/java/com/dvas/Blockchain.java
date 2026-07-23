package com.dvas;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import org.hyperledger.fabric.client.Contract;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public final class Blockchain {

    private static final Gson GSON =
            new Gson();

    private final Contract chaincodeContract;
    private final Pairing pairing;

    public Blockchain(
            final Contract contract,
            final Pairing pairingInstance
    ) {
        this.chaincodeContract = contract;
        this.pairing = pairingInstance;

        System.out.println(
                "Blockchain adapter initialized."
        );
    }

    public String elementToBase64String(
            final Element element
    ) {
        if (element == null) {
            return null;
        }

        return Base64.getEncoder()
                .encodeToString(
                        element.toBytes()
                );
    }

    public Element base64StringToElement(
            final String base64String
    ) {
        if (
            base64String == null ||
            base64String.isBlank()
        ) {
            return null;
        }

        final byte[] bytes =
                Base64.getDecoder()
                        .decode(base64String);

        return pairing.getG1()
                .newElementFromBytes(bytes)
                .getImmutable();
    }

    public void addMapping(
            final String publicKeyBase64,
            final String phiBase64
    ) throws Exception {

        requireNonBlank(
                publicKeyBase64,
                "Public key"
        );

        requireNonBlank(
                phiBase64,
                "Phi_i"
        );

        final byte[] response =
                chaincodeContract.submitTransaction(
                        "addMapping",
                        publicKeyBase64,
                        phiBase64
                );

        System.out.println(
                "addMapping committed: " +
                new String(
                        response,
                        StandardCharsets.UTF_8
                )
        );
    }

    public Element getPhiByPublicKey(
            final Element publicKeyElement
    ) throws Exception {

        final String phiBase64 =
                getPhiBase64DirectlyFromChaincode(
                        publicKeyElement
                );

        return base64StringToElement(
                phiBase64
        );
    }

    public String getPhiBase64DirectlyFromChaincode(
            final Element publicKeyElement
    ) throws Exception {

        if (publicKeyElement == null) {
            throw new IllegalArgumentException(
                    "Public key cannot be null."
            );
        }

        final String publicKeyBase64 =
                elementToBase64String(
                        publicKeyElement
                );

        final byte[] response =
                chaincodeContract.evaluateTransaction(
                        "queryPhi",
                        publicKeyBase64
                );

        final String phiBase64 =
                new String(
                        response,
                        StandardCharsets.UTF_8
                );

        return phiBase64.isBlank()
                ? null
                : phiBase64;
    }

    public List<Map<String, String>>
            queryAllMappings() throws Exception {

        final byte[] response =
                chaincodeContract.evaluateTransaction(
                        "queryAllMappings"
                );

        final String json =
                new String(
                        response,
                        StandardCharsets.UTF_8
                );

        final List<Map<String, String>> mappings =
                GSON.fromJson(
                        json,
                        new TypeToken<
                                List<Map<String, String>>
                        >() {
                        }.getType()
                );

        return mappings == null
                ? List.of()
                : mappings;
    }

    public void printBlockchain()
            throws Exception {

        final List<Map<String, String>> mappings =
                queryAllMappings();

        if (mappings.isEmpty()) {
            System.out.println(
                    "No DVAS mappings found."
            );

            return;
        }

        int index = 1;

        for (Map<String, String> mapping : mappings) {
            System.out.printf(
                    "Mapping %d:%n" +
                    "  PublicKey: %s%n" +
                    "  Phi_i: %s%n",
                    index++,
                    mapping.get("publicKey"),
                    mapping.get("phi")
            );
        }
    }

    private static void requireNonBlank(
            final String value,
            final String fieldName
    ) {
        if (
            value == null ||
            value.isBlank()
        ) {
            throw new IllegalArgumentException(
                    fieldName +
                    " cannot be empty."
            );
        }
    }
}