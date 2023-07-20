package com.malhar.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtService jwtService;

    final private UserDetailsService userDetailsService;

    /**
     *
     * @param request --> our request (contains request info.)
     * @param response --> our response (if you wanna add an extra header)
     * @param filterChain --> Chain of reponsibility design pattern (it contains still of other filters we need to execute)
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        // extracting JWT token
        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            // pass to next filter
            filterChain.doFilter(request, response);
            return;
        }
        // avoiding "Bearer " (as well as the space)
        jwtToken = authHeader.substring(7);

        // need to extract email from JWT token for this we need JWT SERVICE
        userEmail = jwtService.extractUsername(jwtToken);
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // sending data we got from the db
            if(jwtService.isTokenValid(jwtToken, userDetails)){
                // for updating Security context details
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // updating security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
