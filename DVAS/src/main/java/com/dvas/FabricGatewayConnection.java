package com.dvas;

import io.grpc.Grpc;
import io.grpc.ChannelCredentials;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;

import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Hash;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.util.Comparator;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Owns the Fabric Gateway and its underlying gRPC channel.
 *
 * Crypto material is loaded at runtime from the shared Fabric
 * test-network. No Fabric identity is copied into this repository.
 */
public final class FabricGatewayConnection
        implements AutoCloseable {

    private static final String MSP_ID =
            environmentOrDefault(
                    "FABRIC_MSP_ID",
                    "Org1MSP"
            );

    private static final String CHANNEL_NAME =
            environmentOrDefault(
                    "FABRIC_CHANNEL_NAME",
                    "basrchannel"
            );

    private static final String CHAINCODE_NAME =
            environmentOrDefault(
                    "FABRIC_CHAINCODE_NAME",
                    "dvas"
            );

    private static final String PEER_ENDPOINT =
            environmentOrDefault(
                    "FABRIC_PEER_ENDPOINT",
                    "localhost:7051"
            );

    private static final String PEER_HOST_OVERRIDE =
            environmentOrDefault(
                    "FABRIC_PEER_HOST_OVERRIDE",
                    "peer0.org1.example.com"
            );

    private static final String ORG1_USER =
            environmentOrDefault(
                    "FABRIC_ORG1_USER",
                    "User1@org1.example.com"
            );

    private final ManagedChannel grpcChannel;
    private final Gateway gateway;
    private final Contract contract;

    private FabricGatewayConnection(
            final ManagedChannel grpcChannel,
            final Gateway gateway,
            final Contract contract
    ) {
        this.grpcChannel = grpcChannel;
        this.gateway = gateway;
        this.contract = contract;
    }

    public static FabricGatewayConnection connect()
            throws IOException,
            CertificateException,
            InvalidKeyException {

        final Path testNetworkPath =
                resolveTestNetworkPath();

        final Path organizationPath =
                testNetworkPath.resolve(
                        Paths.get(
                                "organizations",
                                "peerOrganizations",
                                "org1.example.com"
                        )
                );

        final Path certificateDirectory =
                organizationPath.resolve(
                        Paths.get(
                                "users",
                                ORG1_USER,
                                "msp",
                                "signcerts"
                        )
                );

        final Path privateKeyDirectory =
                organizationPath.resolve(
                        Paths.get(
                                "users",
                                ORG1_USER,
                                "msp",
                                "keystore"
                        )
                );

        final Path tlsCertificatePath =
                organizationPath.resolve(
                        Paths.get(
                                "peers",
                                "peer0.org1.example.com",
                                "tls",
                                "ca.crt"
                        )
                );

        final Identity identity =
                newIdentity(certificateDirectory);

        final Signer signer =
                newSigner(privateKeyDirectory);

        final ManagedChannel grpcChannel =
                newGrpcConnection(tlsCertificatePath);

        try {
            final Gateway gateway =
                    Gateway.newInstance()
                            .identity(identity)
                            .signer(signer)
                            .hash(Hash.SHA256)
                            .connection(grpcChannel)
                            .evaluateOptions(
                                    options ->
                                            options.withDeadlineAfter(
                                                    5,
                                                    TimeUnit.SECONDS
                                            )
                            )
                            .endorseOptions(
                                    options ->
                                            options.withDeadlineAfter(
                                                    15,
                                                    TimeUnit.SECONDS
                                            )
                            )
                            .submitOptions(
                                    options ->
                                            options.withDeadlineAfter(
                                                    5,
                                                    TimeUnit.SECONDS
                                            )
                            )
                            .commitStatusOptions(
                                    options ->
                                            options.withDeadlineAfter(
                                                    1,
                                                    TimeUnit.MINUTES
                                            )
                            )
                            .connect();

            final Network network =
                    gateway.getNetwork(CHANNEL_NAME);

            final Contract contract =
                    network.getContract(CHAINCODE_NAME);

            System.out.println(
                    "Connected to Fabric Gateway: " +
                    PEER_ENDPOINT
            );

            System.out.println(
                    "Fabric context: MSP=" + MSP_ID +
                    ", channel=" + CHANNEL_NAME +
                    ", chaincode=" + CHAINCODE_NAME
            );

            return new FabricGatewayConnection(
                    grpcChannel,
                    gateway,
                    contract
            );
        } catch (RuntimeException exception) {
            grpcChannel.shutdownNow();
            throw exception;
        }
    }

    public Contract getContract() {
        return contract;
    }

    private static ManagedChannel newGrpcConnection(
            final Path tlsCertificatePath
    ) throws IOException {

        requireRegularFile(
                tlsCertificatePath,
                "Peer TLS certificate"
        );

        final ChannelCredentials credentials =
                TlsChannelCredentials.newBuilder()
                        .trustManager(
                                tlsCertificatePath.toFile()
                        )
                        .build();

        return Grpc.newChannelBuilder(
                        PEER_ENDPOINT,
                        credentials
                )
                .overrideAuthority(
                        PEER_HOST_OVERRIDE
                )
                .build();
    }

    private static Identity newIdentity(
            final Path certificateDirectory
    ) throws IOException, CertificateException {

        final Path certificatePath =
                firstRegularFile(
                        certificateDirectory,
                        "User certificate"
                );

        try (
            var certificateReader =
                    Files.newBufferedReader(
                            certificatePath
                    )
        ) {
            var certificate =
                    Identities.readX509Certificate(
                            certificateReader
                    );

            return new X509Identity(
                    MSP_ID,
                    certificate
            );
        }
    }

    private static Signer newSigner(
            final Path privateKeyDirectory
    ) throws IOException, InvalidKeyException {

        final Path privateKeyPath =
                firstRegularFile(
                        privateKeyDirectory,
                        "User private key"
                );

        try (
            var privateKeyReader =
                    Files.newBufferedReader(
                            privateKeyPath
                    )
        ) {
            var privateKey =
                    Identities.readPrivateKey(
                            privateKeyReader
                    );

            return Signers.newPrivateKeySigner(
                    privateKey
            );
        }
    }

    private static Path firstRegularFile(
            final Path directory,
            final String description
    ) throws IOException {

        if (!Files.isDirectory(directory)) {
            throw new IOException(
                    description +
                    " directory does not exist: " +
                    directory
            );
        }

        try (Stream<Path> files = Files.list(directory)) {
            return files
                    .filter(Files::isRegularFile)
                    .sorted(
                            Comparator.comparing(
                                    Path::toString
                            )
                    )
                    .findFirst()
                    .orElseThrow(
                            () -> new IOException(
                                    description +
                                    " not found in: " +
                                    directory
                            )
                    );
        }
    }

    private static void requireRegularFile(
            final Path path,
            final String description
    ) throws IOException {

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    description +
                    " does not exist: " +
                    path
            );
        }
    }

    private static Path resolveTestNetworkPath() {
        final String configuredPath =
                System.getenv(
                        "FABRIC_TEST_NETWORK_PATH"
                );

        if (
            configuredPath != null &&
            !configuredPath.isBlank()
        ) {
            return Paths.get(configuredPath)
                    .toAbsolutePath()
                    .normalize();
        }

        return Paths.get(
                        System.getProperty("user.home"),
                        "basr",
                        "blockchain",
                        "fabric-samples",
                        "test-network"
                )
                .toAbsolutePath()
                .normalize();
    }

    private static String environmentOrDefault(
            final String variableName,
            final String defaultValue
    ) {
        final String value =
                System.getenv(variableName);

        return value == null || value.isBlank()
                ? defaultValue
                : value;
    }

    @Override
    public void close() throws InterruptedException {
        gateway.close();

        grpcChannel.shutdownNow();

        if (
            !grpcChannel.awaitTermination(
                    5,
                    TimeUnit.SECONDS
            )
        ) {
            System.err.println(
                    "Fabric gRPC channel did not terminate " +
                    "within 5 seconds."
            );
        }
    }
}