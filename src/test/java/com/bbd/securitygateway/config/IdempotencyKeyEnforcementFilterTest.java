package com.bbd.securitygateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IdempotencyKeyEnforcementFilterTest {

    private static final String HEADER = "Idempotency-Key";

    private final IdempotencyKeyEnforcementFilter filter = new IdempotencyKeyEnforcementFilter();

    @Test
    void user_scim_post는_idempotency_key가_없어도_gateway_필수검사에서_제외한다() throws Exception {
        MockHttpServletRequest request = post("/user/scim/v2/Users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
    }

    @Test
    void user_scim_post에_idempotency_key가_있으면_헤더를_제거하지_않고_그대로_넘긴다() throws Exception {
        MockHttpServletRequest request = post("/user/scim/v2/Users");
        request.addHeader(HEADER, "scim-request-1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertEquals("scim-request-1", ((MockHttpServletRequest) chain.getRequest()).getHeader(HEADER));
    }

    @Test
    void user_scim_prefix와_겹치는_다른_user_post는_idempotency_key를_계속_요구한다() throws Exception {
        MockHttpServletRequest request = post("/user/scim-users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(400, response.getStatus());
        assertEquals("{\"code\":\"IDEM400\",\"message\":\"Idempotency-Key 헤더가 필요합니다.\"}",
                response.getContentAsString());
    }

    @Test
    void 일반_user_post는_idempotency_key를_계속_요구한다() throws Exception {
        MockHttpServletRequest request = post("/user/internal/users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertEquals(400, response.getStatus());
    }

    private MockHttpServletRequest post(String uri) {
        return new MockHttpServletRequest("POST", uri);
    }
}
