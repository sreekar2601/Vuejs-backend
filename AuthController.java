package com.tekhive.spring.security.postgresql.controllers;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.management.AttributeNotFoundException;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.tekhive.spring.security.postgresql.models.User;
import com.tekhive.spring.security.postgresql.payload.request.LoginRequest;
import com.tekhive.spring.security.postgresql.payload.request.SignupRequest;
import com.tekhive.spring.security.postgresql.payload.request.UserUpdateRequest;
import com.tekhive.spring.security.postgresql.payload.response.JwtResponse;
import com.tekhive.spring.security.postgresql.payload.response.MessageResponse;
import com.tekhive.spring.security.postgresql.repository.UserRepository;
import com.tekhive.spring.security.postgresql.security.jwt.JwtUtils;
import com.tekhive.spring.security.postgresql.security.services.UserDetailsImpl;

@CrossOrigin(origins = "http://127.0.0.1:5173/", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;
	


	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	 
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();		
		

		return ResponseEntity.ok(new JwtResponse(jwt, 
												 userDetails.getId(), 
												 userDetails.getUsername(), 
												 userDetails.getEmail()
												));
	}



	@RequestMapping(value="/update/{id}",method = RequestMethod.PUT)
	public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody UserUpdateRequest userUpdateRequest) {
	    
	    User user = userRepository.findById(id).orElse(null);
	    if (user == null) {
	        return ResponseEntity.notFound().build();
	    }

	    if (userUpdateRequest.getEmail() != null && !userUpdateRequest.getEmail().isEmpty()) {
	        user.setEmail(userUpdateRequest.getEmail());
	    }

	    if (userUpdateRequest.getPhoneNumber() != null) {
	        user.setPhoneNumber(userUpdateRequest.getPhoneNumber());
	    }

	    if (userUpdateRequest.getLocation() != null && !userUpdateRequest.getLocation().isEmpty()) {
	        user.setLocation(userUpdateRequest.getLocation());
	    }

	    if (userUpdateRequest.getGender() != null && !userUpdateRequest.getGender().isEmpty()) {
	        user.setGender(userUpdateRequest.getGender());
	    }

	    if (userUpdateRequest.getFullName() != null && !userUpdateRequest.getFullName().isEmpty()) {
	        user.setFullName(userUpdateRequest.getFullName());
	    }

	    if (userUpdateRequest.getBio() != null && !userUpdateRequest.getBio().isEmpty()) {
	        user.setBio(userUpdateRequest.getBio());
	    }

	    if (userUpdateRequest.getUsername() != null && !userUpdateRequest.getUsername().isEmpty()) {
	        user.setUsername(userUpdateRequest.getUsername());
	    }

	    User updatedUser = userRepository.save(user);

	    return ResponseEntity.ok().body(updatedUser);
	}


		
		
	
		 @GetMapping("/user/{id}")
		    public ResponseEntity<User> getUserById(@PathVariable Long id) throws AttributeNotFoundException {
		        User user = userRepository.findById(id)
		                .orElseThrow(() -> new AttributeNotFoundException("User not found with id: " + id));
		        // Set the password field to null before returning the user
		        user.setPassword(null);
		        return new ResponseEntity<User>(user, HttpStatus.OK);
		    }

		 
		 
		 
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(), 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));

		

		

		user.setUpdatedAt(LocalDateTime.now());
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
}
