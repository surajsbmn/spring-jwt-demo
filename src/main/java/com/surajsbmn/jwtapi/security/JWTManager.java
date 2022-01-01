package com.surajsbmn.jwtapi.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.surajsbmn.jwtapi.model.Role;
import com.surajsbmn.jwtapi.model.User;
import com.surajsbmn.jwtapi.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Component
public class JWTManager {

    @Value("${jwt.secret}")
    private String JWT_SECRET;

    private final Integer ACCESS_TOKEN_EXPIRY = 10;
    private final Integer REFRESH_TOKEN_EXPIRY = 60;

    @Autowired
    private UserService userService;

    public String getJWT_SECRET() {
        return JWT_SECRET;
    }

    public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorizationHeader) {
        String token = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC256(getJWT_SECRET().getBytes(StandardCharsets.UTF_8));
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        Arrays.stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }


    public String refreshAccessToken(String refreshToken, String url){
        Algorithm algorithm = Algorithm.HMAC256(getJWT_SECRET().getBytes(StandardCharsets.UTF_8));
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);
        String username = decodedJWT.getSubject();
        User user = userService.getUser(username);
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY * 60 * 1000))
                .withIssuer(url)
                .withClaim("roles", user.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toList()))
                .sign(algorithm);
    }
}
