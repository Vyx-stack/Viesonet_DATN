package com.viesonet.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.viesonet.entity.JwtRequestModel;
import com.viesonet.entity.JwtResponseModel;
import com.viesonet.security.AuthConfig;
import com.viesonet.security.JwtTokenUtil;

@RestController
public class LoginController {

	@Autowired
	AuthConfig authConfig;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	JwtTokenUtil jwtTokenUtil;

	@GetMapping("/api/login")
	public ModelAndView getLoginPage() {
		ModelAndView modelAndView = new ModelAndView("Login");
		return modelAndView;
	}

	@RequestMapping(value = "/api/login", method = RequestMethod.POST)
	public ResponseEntity<JwtResponseModel> createToken(@RequestBody JwtRequestModel request) throws Exception {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			
			final String jwtToken = jwtTokenUtil.generateToken(request.getUsername());
			return ResponseEntity.ok(new JwtResponseModel(jwtToken));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}

}
