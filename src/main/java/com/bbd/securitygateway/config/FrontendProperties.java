package com.bbd.securitygateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "security-gateway.frontend")
public class FrontendProperties {

    private String baseUrl;
    private String allowedOrigins;
    private String loginPath = "/login";
    private String mainPath = "/main";

    public String loginUrl() {
        return url(loginPath);
    }

    public String loginSessionErrorUrl() {
        return loginUrl() + "?error=session";
    }

    public String loginExpiredUrl() {
        return loginUrl() + "?expired=true";
    }

    public String mainUrl() {
        return url(mainPath);
    }

    public List<String> allowedOrigins() {
        String origins = hasText(allowedOrigins) ? allowedOrigins : baseUrl;

        return Arrays.stream(origins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .map(this::removeTrailingSlash)
                .toList();
    }

    private String url(String path) {
        return normalizedBaseUrl() + normalizedPath(path);
    }

    private String normalizedBaseUrl() {
        if (!hasText(baseUrl)) {
            throw new IllegalStateException("security-gateway.frontend.base-url 설정이 필요합니다.");
        }

        return removeTrailingSlash(baseUrl.trim());
    }

    private String normalizedPath(String path) {
        if (!hasText(path)) {
            return "";
        }

        String trimmedPath = path.trim();
        return trimmedPath.startsWith("/") ? trimmedPath : "/" + trimmedPath;
    }

    private String removeTrailingSlash(String value) {
        String normalized = value;
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(String allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public String getLoginPath() {
        return loginPath;
    }

    public void setLoginPath(String loginPath) {
        this.loginPath = loginPath;
    }

    public String getMainPath() {
        return mainPath;
    }

    public void setMainPath(String mainPath) {
        this.mainPath = mainPath;
    }
}
