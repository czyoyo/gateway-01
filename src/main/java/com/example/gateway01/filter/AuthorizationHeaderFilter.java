package com.example.gateway01.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final String configKey;

    public static class Config {
        // 아직 설정 할 옵션이 없으므로 비워둠
    }

    //생성시 Config class를 상속받은 Factory로 넘겨줘야해서 lombok을 사용하지 않고 다음과 같이 처리
    public AuthorizationHeaderFilter(
        @Value("${token.secret}") String configKey
    ) {
        super(Config.class);
        this.configKey = configKey;
    }

    // 토큰 검증
    @Override
    public GatewayFilter apply(Config config) {

        return ((exchange, chain) -> {
            ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

            // 헤더에 Authorization이 있는지 확인 후 없으면 에러
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Authorization header is not exist");
            }

            String authorizationHeader = request.getHeaders().get("Authorization").get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            // 토큰이 유효한지 확인
            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT is not valid");
            }

            // 토큰이 유효하면 다음 필터로 넘어감
            return chain.filter(exchange);
        });
    }


    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        String subject = null;

        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(configKey.getBytes()))
                .build()
                .parseClaimsJws(jwt)
                .getBody();

            subject = claims.getSubject();

        } catch (Exception ex) {
            returnValue = false;
        }

        // 토큰이 없거나 subject가 없으면 false
        if(subject == null || subject.isEmpty()) {
            returnValue = false;
        }
        if (jwt == null || jwt.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }



    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        log.error(err);
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }



}
