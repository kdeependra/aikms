package com.aikms.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Attaches a correlation ID to every inbound request.
 * Downstream services can propagate this ID for distributed tracing.
 */
@Slf4j
@Component
public class CorrelationIdFilter implements GlobalFilter, Ordered {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String correlationId = request.getHeaders().getFirst(CORRELATION_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }
        final String finalId = correlationId;
        ServerHttpRequest mutated = request.mutate()
                .header(CORRELATION_HEADER, finalId)
                .build();
        log.debug("Request: {} {} correlationId={}", mutated.getMethod(), mutated.getPath(), finalId);
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @Override
    public int getOrder() { return -100; }
}
