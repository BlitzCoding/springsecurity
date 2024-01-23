package yonghlee.springsecurity.service.Impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

/**
 * JWT를 생성하고 처리하는 클래스
 * Claims는 JWT의 데이터 조각을 나타냄 (헤더, 페이로드, 시그니쳐) 즉 사용자, 발행자, 만료 시간같은 특ㅈ성
 */
@Service
public class JWTServiceImpl {

    /**
     * 사용자 정보(UserDetails)를 기반으로 JWT 토큰을 생성
     * 사용자 이름, 토큰 발행 시간, 토큰 만료 시간, 서명 알고리즘 설정
     * 서명 후 문자열 반환
     */
    private String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 60 * 24))
                .signWith(getSiginKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 토큰에서 사용자 이름 추출함
     */
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 주어진 토큰에서 모든 클레임 추출하고, 클레임을 해석하는 함수를 적용하여 특정 클레임의 값을 반환
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers)
    {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private Key getSiginKey() {
        byte[] key = Decoders.BASE64.decode("413F4428472B4B6250655368566D5970337336763979244226452948404D6351");
        return Keys.hmacShaKeyFor(key);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSiginKey()).build().parseClaimsJws(token).getBody();
    }


    //

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}
