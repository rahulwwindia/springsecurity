package org.krams.tutorial.manager;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.krams.tutorial.dao.UserDAO;
import org.krams.tutorial.domain.DbUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

/**
 * A custom authentication manager that allows access if the user details
 * exist in the database and if the username and password are not the same.
 * Otherwise, throw a {@link BadCredentialsException}
 */
public class CustomAuthenticationManager implements AuthenticationManager {

	protected static Logger logger = Logger.getLogger("service");

	// Our custom DAO layer
	private UserDAO userDAO = new UserDAO();

	// We need an Md5 encoder since our passwords in the database are Md5 encoded. 
	private Md5PasswordEncoder passwordEncoder = new Md5PasswordEncoder();
	
	public Authentication authenticate(Authentication auth)
			throws AuthenticationException {

		logger.debug("Performing custom authentication");
		
		// Init a database user object
		DbUser user = null;
		
		try {
			// Retrieve user details from database
			user = userDAO.searchDatabase(auth.getName());
		} catch (Exception e) {
			logger.error("User does not exists!");
			throw new BadCredentialsException("User does not exists!");
		}
		
		// Compare passwords
		// Make sure to encode the password first before comparing
		if (  passwordEncoder.isPasswordValid(user.getPassword(), (String) auth.getCredentials(), null) == false ) {
			logger.error("Wrong password!");
			throw new BadCredentialsException("Wrong password!");
		}
		
		// Here's the main logic of this custom authentication manager
		// Username and password must be the same to authenticate
		if (auth.getName().equals(auth.getCredentials()) == true) {
			logger.debug("Entered username and password are the same!");
			throw new BadCredentialsException("Entered username and password are the same!");
			
		} else {
			
			logger.debug("User details are good and ready to go");
			return new UsernamePasswordAuthenticationToken(
					auth.getName(), 
					auth.getCredentials(), 
					getAuthorities(user.getAccess()));
		}
	}
	
	/**
	 * Retrieves the correct ROLE type depending on the access level, where access level is an Integer.
	 * Basically, this interprets the access value whether it's for a regular user or admin.
	 * 
	 * @param access an integer value representing the access of the user
	 * @return collection of granted authorities
	 */
	 public Collection<GrantedAuthority> getAuthorities(Integer access) {
			// Create a list of grants for this user
			List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>(2);
			
			// All users are granted with ROLE_USER access
			// Therefore this user gets a ROLE_USER by default
			logger.debug("Grant ROLE_USER to this user");
			authList.add(new GrantedAuthorityImpl("ROLE_USER"));
			
			// Check if this user has admin access 
			// We interpret Integer(1) as an admin user
			if ( access.compareTo(1) == 0) {
				// User has admin access
				logger.debug("Grant ROLE_ADMIN to this user");
				authList.add(new GrantedAuthorityImpl("ROLE_ADMIN"));
			}

			// Return list of granted authorities
			return authList;
	  }

}
