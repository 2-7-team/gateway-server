package com._7.bookinghospital.gateway.infrastructure.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import javax.crypto.SecretKey;

@Component
public class JwtTokenProvider {
    private final Logger log = LoggerFactory.getLogger("gateway - jwt token provider");
    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final SecretKey secretKey;

    public JwtTokenProvider(@Value("${service.jwt.secret-key}") String secretKey) {
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    //유효성
    public boolean validateToken(String token) {
        log.info("token: {}", token);
        try{
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }

    // Claims 추출
    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractToken(ServerWebExchange exchange){
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            log.info(authHeader);
            return authHeader.substring(7);
        }
        return null;
    }

    // 토큰 추출
    // 어떤 방법이 더 효율적인가? 더 좋은 방법이 무엇인가?
    // 1. UserInfo.class: (유효성이 검증된 토큰을 분해하고, 사용자의 정보를 얻어서 객체에 담아서 헤더에 실어서 요청 서비스에 보낸다.)
    // 2. 토큰처럼 String 타입으로 유저의 정보를 헤더에 담아서 보낸다.


}
