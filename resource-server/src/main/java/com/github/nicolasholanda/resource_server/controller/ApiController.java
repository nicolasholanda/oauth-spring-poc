package com.github.nicolasholanda.resource_server.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class ApiController {

    @GetMapping("/public/hello")
    public Map<String, String> publicEndpoint() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a public endpoint");
        return response;
    }

    @GetMapping("/api/protected")
    public Map<String, Object> protectedEndpoint(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a protected endpoint - token required");
        response.put("subject", jwt.getSubject());
        response.put("issuer", jwt.getIssuer());
        response.put("scopes", jwt.getClaimAsStringList("scope"));
        return response;
    }

    @GetMapping("/api/user")
    public Map<String, Object> userInfo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> response = new HashMap<>();
        response.put("username", jwt.getSubject());
        response.put("token_issued_at", jwt.getIssuedAt());
        response.put("token_expires_at", jwt.getExpiresAt());
        response.put("all_claims", jwt.getClaims());
        return response;
    }
}
