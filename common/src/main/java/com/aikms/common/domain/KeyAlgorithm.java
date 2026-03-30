package com.aikms.common.domain;

public enum KeyAlgorithm {
    AES_128_GCM("AES", 128, "AES/GCM/NoPadding"),
    AES_256_GCM("AES", 256, "AES/GCM/NoPadding"),
    AES_128_CBC("AES", 128, "AES/CBC/PKCS5Padding"),
    AES_256_CBC("AES", 256, "AES/CBC/PKCS5Padding"),
    RSA_2048("RSA", 2048, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
    RSA_3072("RSA", 3072, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
    RSA_4096("RSA", 4096, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
    EC_P256("EC", 256, "EC"),
    EC_P384("EC", 384, "EC"),
    EC_P521("EC", 521, "EC"),
    ED25519("EdDSA", 255, "Ed25519"),
    HMAC_SHA256("HmacSHA256", 256, "HmacSHA256"),
    HMAC_SHA384("HmacSHA384", 384, "HmacSHA384"),
    HMAC_SHA512("HmacSHA512", 512, "HmacSHA512");

    private final String jcaName;
    private final int keySizeBits;
    private final String cipherTransformation;

    KeyAlgorithm(String jcaName, int keySizeBits, String cipherTransformation) {
        this.jcaName = jcaName;
        this.keySizeBits = keySizeBits;
        this.cipherTransformation = cipherTransformation;
    }

    public String getJcaName()              { return jcaName; }
    public int getKeySizeBits()             { return keySizeBits; }
    public String getCipherTransformation() { return cipherTransformation; }

    public boolean isSymmetric() {
        return jcaName.startsWith("AES") || jcaName.startsWith("Hmac");
    }

    public boolean isAsymmetric() {
        return !isSymmetric();
    }
}
