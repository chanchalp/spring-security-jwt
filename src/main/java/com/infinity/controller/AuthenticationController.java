package com.infinity.controller;

import static com.infinity.model.Constants.HEADER_STRING;
import static com.infinity.model.Constants.TOKEN_PREFIX;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.infinity.config.TokenProvider;
import com.infinity.model.AuthToken;
import com.infinity.model.LoginUser;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/token")
public class AuthenticationController {
	
	//public static final Logger LOGGER = Logger.getLogger(AuthenticationController.class);
	private static final String TOKEN_FLAG="isValidToken";
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenProvider jwtTokenUtil;

    
    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping(value = "/generate-token", method = RequestMethod.POST)
    public ResponseEntity<?> register(@RequestBody LoginUser loginUser) throws AuthenticationException {

        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginUser.getUsername(),
                        loginUser.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        final String token = jwtTokenUtil.generateToken(authentication);
        return ResponseEntity.ok(new AuthToken(token));
    }

	
	  @RequestMapping(value = "/validate-token", method = RequestMethod.GET)
	  public Map<String,String> validateToken(HttpServletRequest request) {
		  String header = request.getHeader(HEADER_STRING);
		  String username = null;
	        String authToken = null;
	        Map<String,String> resultMap=new HashMap<>();
	        if (header != null && header.startsWith(TOKEN_PREFIX)) {
	            authToken = header.replace(TOKEN_PREFIX,"");
	            try {
	                username = jwtTokenUtil.getUsernameFromToken(authToken);
	            } catch (IllegalArgumentException e) {
	               // logger.error("an error occured during getting username from token", e);
	            	System.out.println("an error occured during getting username from token");
	            } catch (ExpiredJwtException e) {
	              //  logger.warn("the token is expired and not valid anymore", e);
	            	System.out.println("the token is expired and not valid anymore");
	            } catch(SignatureException e){
	              //  logger.error("Authentication Failed. Username or Password not valid.");
	            	System.out.println("Authentication Failed. Username or Password not valid.");
	            }
	        } else {
	           // logger.warn("couldn't find bearer string, will ignore the header");
	        	System.out.println("couldn't find bearer string, will ignore the header");
	        }
	        if (username != null) {

	            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

	            if (jwtTokenUtil.validateToken(authToken, userDetails)) {
	                UsernamePasswordAuthenticationToken authentication = jwtTokenUtil.getAuthentication(authToken, SecurityContextHolder.getContext().getAuthentication(), userDetails);
	                //UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));
	                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	                //logger.info("authenticated user " + username + ", setting security context");
	                System.out.println("authenticated user " + username + ", setting security context");
	                SecurityContextHolder.getContext().setAuthentication(authentication);
	                resultMap.put(TOKEN_FLAG,"true");
	                for(GrantedAuthority authority:authentication.getAuthorities()) {
	                	String role=authority.getAuthority();
	                	resultMap.put(role, "true");
	                }
	            }
	        }
	        return resultMap;
		  
	  }
	 
    
}
