package com.tekcit.gateway.config.security.jwt;

import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    @Value("${jwt.private-pem-path}")
    private org.springframework.core.io.Resource privatePemPath;

    @Value("${jwt.public-pem-path}")
    private org.springframework.core.io.Resource publicPemPath;



    private PrivateKey privateKey;
    private PublicKey publicKey;



    @PostConstruct
    public void init() {
        try {
            // 파일에서 PEM 내용 읽기
            String privatePem = new String(privatePemPath.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            String publicPem  = new String(publicPemPath.getInputStream().readAllBytes(),  java.nio.charset.StandardCharsets.UTF_8);

            this.privateKey = loadPrivateKeyFromPem(privatePem);
            this.publicKey  = loadPublicKeyFromPem(publicPem);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read PEM files", e);
        }
    }


    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .setAllowedClockSkewSeconds(30)  // 시계 오차 30초 허용
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token.");
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token.");
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token.");
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature.");
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims is empty.");
        }
        return false;
    }

    // Spring Jwt
    public Jwt convertToSpringJwt(String token) {
        Claims claims = getAllClaims(token);

        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256"); // 알고리즘 등 필요에 따라 세팅

        Map<String, Object> claimsMap = new HashMap<>(claims);

        Integer expInt = (Integer) claims.get("exp");
        Integer iatInt = (Integer) claims.get("iat");

        Instant expiresAt = Instant.ofEpochSecond(expInt.longValue());
        Instant issuedAt = Instant.ofEpochSecond(iatInt.longValue());

        return new Jwt(token, issuedAt, expiresAt, headers, claimsMap);
    }

    //  Claim 추출
    public Claims getAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .setAllowedClockSkewSeconds(30)  // 시계 오차 30초 허용
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public String getClaimAsString(Claims claims, String claimName){
        return claims.get(claimName).toString();
    }
    public String getClaimAsString(String token, String clameName){
        Claims claims = getAllClaims(token);
        return getClaimAsString(claims, clameName);
    }
    public String getRole(String token){
        Claims claims = getAllClaims(token);
        return getRole(claims);
    }
    public String getRole(Claims claims){
        return claims.get("role", String.class);
    }
    public String getName(String token){
        Claims claims = getAllClaims(token);
        return getName(claims);
    }

    public String getName(Claims claims){
        return claims.get("name", String.class);
    }

    // ===== PEM 로더들
    private static PrivateKey loadPrivateKeyFromPem(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(content);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA private key", e);
        }
    }

    private static PublicKey loadPublicKeyFromPem(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(content);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA public key", e);
        }
    }
}

