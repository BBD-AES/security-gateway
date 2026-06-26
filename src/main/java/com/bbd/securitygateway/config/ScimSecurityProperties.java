package com.bbd.securitygateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "security-gateway.scim")
public class ScimSecurityProperties {

    private List<String> allowedClientIds = new ArrayList<>(List.of("user-admin-console-admin"));

    public List<String> getAllowedClientIds() {
        return allowedClientIds;
    }

    public void setAllowedClientIds(List<String> allowedClientIds) {
        this.allowedClientIds = allowedClientIds == null ? new ArrayList<>() : allowedClientIds;
    }
}
