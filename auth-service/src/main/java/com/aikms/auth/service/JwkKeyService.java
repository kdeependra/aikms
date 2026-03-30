package com.aikms.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Manages the RSA signing key pair used for JWT issuance.
 *
 * In production these keys should be retrieved from Vault (spring.cloud.vault).
 * For development they are generated in-memory on startup.
 */
@Slf4j
@Service
public class JwkKeyService {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey  publicKey;
    private final String        keyId;

    public JwkKeyService(@Value("${aikms.auth.jwt.key-bits:2048}") int keyBits) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(keyBits, new SecureRandom());
            KeyPair kp = gen.generateKeyPair();
            this.privateKey = (RSAPrivateKey) kp.getPrivate();
            this.publicKey  = (RSAPublicKey)  kp.getPublic();
            this.keyId      = UUID.randomUUID().toString();
            log.info("JWT signing key generated: kid={} bits={}", keyId, keyBits);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA key generation failed", ex);
        }
    }

    public RSAPrivateKey getPrivateKey() { return privateKey; }
    public RSAPublicKey  getPublicKey()  { return publicKey;  }
    public String        getKeyId()      { return keyId;      }
    public Key           getKey()        { return publicKey;  }
}
