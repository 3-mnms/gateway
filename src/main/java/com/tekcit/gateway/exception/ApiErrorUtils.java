package com.tekcit.gateway.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public final class ApiErrorUtils {

    private ApiErrorUtils() {}

    public static Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String code, String message) {
        if (exchange.getResponse().isCommitted()) return Mono.empty();

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format(
                "{\"success\":false," +
                        "\"errorCode\":\"%s\"," +
                        "\"errorMessage\":\"%s\"}",
                code, escape(message)
        );

        var buf = exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return exchange.getResponse().writeWith(Mono.just(buf));
    }

    public static Mono<Void> unauthorized(ServerWebExchange ex, String code, String msg) {
        return write(ex, HttpStatus.UNAUTHORIZED, code, msg);
    }

    public static Mono<Void> forbidden(ServerWebExchange ex, String code, String msg) {
        return write(ex, HttpStatus.FORBIDDEN, code, msg);
    }

    public static Mono<Void> badRequest(ServerWebExchange ex, String code, String msg) {
        return write(ex, HttpStatus.BAD_REQUEST, code, msg);
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\"", "\\\"");
    }
}