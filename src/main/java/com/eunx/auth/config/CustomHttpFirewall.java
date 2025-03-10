package com.eunx.auth.config;

import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import javax.servlet.http.HttpServletRequest;

public class CustomHttpFirewall extends StrictHttpFirewall {

    @Override
    public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
        String path = request.getRequestURI();
        if (path != null && path.contains("%0A")) {
            System.out.println("Allowing request with %0A in URL: " + path); // Debug log
            return new FirewalledRequest(request) {
                @Override
                public void reset() {
                    // No-op
                }
            };
        }
        return super.getFirewalledRequest(request);
    }
}