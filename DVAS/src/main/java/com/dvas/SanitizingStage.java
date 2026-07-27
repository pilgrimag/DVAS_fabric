package com.dvas;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.List;

// 不需要 MessageDigest 和 NoSuchAlgorithmException，因为 fmod 被注释掉了
// import java.security.MessageDigest;
// import java.security.NoSuchAlgorithmException;

import com.dvas.Setup;

public class SanitizingStage {

    private Pairing pairing;
    private Setup setup;

    public SanitizingStage(Setup setup) {
        this.pairing = setup.pairing;
        this.setup = setup; // 确保 setup 成员变量被初始化
    }

    // 新增一个内部类来存储细分时间，作为 verifySignature 的返回类型
    public static class SanitizingSubTimings {
        public long offChainComputeTime; // 纯链下密码学计算时间 (纳秒)
        public long fabricQueryTime;     // Fabric 链码查询时间 (纳秒)
        public boolean result;           // 验证结果

        public SanitizingSubTimings(long offChainComputeTime, long fabricQueryTime, boolean result) {
            this.offChainComputeTime = offChainComputeTime;
            this.fabricQueryTime = fabricQueryTime;
            this.result = result;
        }
    }


    /**
     * Verifies one original DVAS signature without Fabric access
     * and without sanitizing the report.
     *
     * @param publicKey sensor public key U_i
     * @param message original report and authorization policy
     * @param signature original signature sigma_i
     * @param generator system generator P
     * @param phi audit component Phi_i
     * @return true when the original signature is valid
     */
    public boolean verifyOriginalSignatureOffChain(
            final Element publicKey,
            final Message message,
            final com.dvas.Sign.Signature signature,
            final Element generator,
            final Element phi) {

        requireNonNull(publicKey, "Public key");
        requireNonNull(message, "Message");
        requireNonNull(signature, "Signature");
        requireNonNull(generator, "Generator");
        requireNonNull(phi, "Phi_i");

        final Element h0 =
                setup.H0(
                        message.getM(),
                        signature.getV_i(),
                        phi
                );

        final Element h1 =
                setup.H1(
                        message.getM(),
                        signature.getV_i(),
                        phi
                );

        return pairingCheck(
                signature,
                publicKey,
                h0,
                generator,
                h1
        );
    }

    /**
     * Sanitizes one already verified ADM report and updates its
     * signature without performing Fabric access.
     *
     * @param publicKey sensor public key U_i
     * @param sanitizerPrivateKey EN private key x
     * @param message mutable report and authorization policy
     * @param signature mutable original signature
     * @param generator system generator P
     * @param designatedVerifierPublicKey DV public key Y
     */
    public void sanitizeVerifiedSignatureOffChain(
            final Element publicKey,
            final Element sanitizerPrivateKey,
            final Message message,
            final com.dvas.Sign.Signature signature,
            final Element generator,
            final Element designatedVerifierPublicKey) {

        requireNonNull(publicKey, "Public key");
        requireNonNull(
                sanitizerPrivateKey,
                "Sanitizer private key"
        );
        requireNonNull(message, "Message");
        requireNonNull(signature, "Signature");
        requireNonNull(generator, "Generator");
        requireNonNull(
                designatedVerifierPublicKey,
                "Designated-verifier public key"
        );

        final Element vPrime =
                setup.pairing.getZr()
                        .newRandomElement()
                        .getImmutable();

        final Element vPointPrime =
                generator.duplicate()
                        .mulZn(vPrime)
                        .getImmutable();

        final String sanitizedMessage =
                fmod(message.getM(), setup);

        final Element sharedPairing =
                pairing.pairing(
                        publicKey,
                        designatedVerifierPublicKey
                );

        final Element tPrime =
                setup.H(
                        sanitizedMessage,
                        message.getOmega(),
                        sharedPairing.powZn(
                                sanitizerPrivateKey
                        )
                );

        final Element phiPrime =
                designatedVerifierPublicKey
                        .duplicate()
                        .mulZn(tPrime)
                        .mulZn(sanitizerPrivateKey)
                        .getImmutable();

        final Element h0Prime =
                setup.H0(
                        sanitizedMessage,
                        vPointPrime,
                        phiPrime
                );

        final Element h1Prime =
                setup.H1(
                        sanitizedMessage,
                        vPointPrime,
                        phiPrime
                );

        final Element tSignaturePrime =
                h0Prime.duplicate()
                        .mulZn(sanitizerPrivateKey)
                        .add(
                                h1Prime.duplicate()
                                        .mulZn(vPrime)
                        )
                        .getImmutable();

        signature.setT_i(tSignaturePrime);
        signature.setV_i(vPointPrime);
        signature.setPhi_i(phiPrime);
        message.setM(sanitizedMessage);
    }

    /**
     * Real-system verification and optional sanitization path.
     * Fabric lookup time and off-chain cryptographic time remain
     * separately observable for the system benchmark.
     */
    public SanitizingSubTimings verifySignature(
            final Setup setup,
            final Element publicKey,
            final List<Element> publicKeys,
            final Element sanitizerPrivateKey,
            final Message message,
            final com.dvas.Sign.Signature signature,
            final Element generator,
            final Element designatedVerifierPublicKey,
            final Blockchain blockchain,
            final List<Integer> adm) {

        if (!publicKeys.contains(publicKey)) {
            return new SanitizingSubTimings(
                    0,
                    0,
                    false
            );
        }

        try {
            if (setup == null) {
                throw new IllegalStateException(
                        "Setup object is not initialized."
                );
            }

            final long fabricStart =
                    System.nanoTime();

            final Element phi =
                    blockchain.getPhiByPublicKey(
                            publicKey
                    );

            final long fabricQueryTime =
                    System.nanoTime() - fabricStart;

            if (phi == null) {
                return new SanitizingSubTimings(
                        0,
                        fabricQueryTime,
                        false
                );
            }

            final long computeStart =
                    System.nanoTime();

            final boolean valid =
                    verifyOriginalSignatureOffChain(
                            publicKey,
                            message,
                            signature,
                            generator,
                            phi
                    );

            if (!valid) {
                return new SanitizingSubTimings(
                        System.nanoTime() - computeStart,
                        fabricQueryTime,
                        false
                );
            }

            if (adm.contains(signature.getId())) {
                sanitizeVerifiedSignatureOffChain(
                        publicKey,
                        sanitizerPrivateKey,
                        message,
                        signature,
                        generator,
                        designatedVerifierPublicKey
                );
            }

            return new SanitizingSubTimings(
                    System.nanoTime() - computeStart,
                    fabricQueryTime,
                    true
            );
        } catch (Exception exception) {
            exception.printStackTrace();

            return new SanitizingSubTimings(
                    0,
                    0,
                    false
            );
        }
    }

    private static void requireNonNull(
            final Object value,
            final String fieldName) {

        if (value == null) {
            throw new IllegalArgumentException(
                    fieldName + " cannot be null."
            );
        }
    }

    // 双线性映射验证
    private boolean pairingCheck(
            final com.dvas.Sign.Signature signature,
            final Element publicKey,
            final Element h0,
            final Element generator,
            final Element h1) {

        final Element leftSide =
                pairing.pairing(
                        signature.getT_i(),
                        generator
                );

        final Element rightSide =
                pairing.pairing(
                        h0,
                        publicKey
                ).mul(
                        pairing.pairing(
                                h1,
                                signature.getV_i()
                        )
                );

        return leftSide.isEqual(rightSide);
    }

    /**
     * Deterministic masking desensitization rule.
     *
     * <p>Each UTF-16 code unit is replaced with {@code '*'}.
     * The benchmark uses ASCII sensor reports, so this preserves
     * both the character length and the UTF-8 byte length while
     * ensuring that protected content is not retained.</p>
     *
     * <p>Rule identifier: DVAS_MASK_V1.</p>
     *
     * @param m original sensitive message
     * @param setup retained for interface compatibility
     * @return masked message with the same character length
     */
    public static String fmod(
            final String m,
            final Setup setup) {

        if (m == null) {
            throw new IllegalArgumentException(
                    "Sensitive message cannot be null."
            );
        }

        if (m.isEmpty()) {
            return m;
        }

        return "*".repeat(m.length());
    }
}