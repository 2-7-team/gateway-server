package com._7.bookinghospital.gateway.application.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com._7.bookinghospital.gateway.infrastructure.jwt.JwtTokenProvider;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

// @S
@Component
public class AuthenticationFilter implements GlobalFilter {
	private final Logger log = LoggerFactory.getLogger("globalFilter");

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		String path = exchange.getRequest().getURI().getPath();
		if (path.equals("/api/users/signin") || path.equals("/api/users/signup")) {
			return chain.filter(exchange);  // /signIn,signUp 경로는 필터를 적용하지 않음
		}

		String token = jwtTokenProvider.extractToken(exchange);

		if (token == null || !jwtTokenProvider.validateToken(token)) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}

		// 토큰 정보 분해, 사용자 정보 header 에 담아서 요청 url 로 보내기
		Claims claims = jwtTokenProvider.getClaims(token);
		String userRole = claims.get("role", String.class);
		String username = claims.getSubject();

		ServerWebExchange build = exchange.mutate()
			.request(r -> r.headers(headers -> {
				headers.set("X-User-Name", username);
				headers.set("X-User-Role", userRole);
			}))
			.build();

		return chain.filter(build);
	}

}
