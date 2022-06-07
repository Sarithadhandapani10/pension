package com.cts.authorization.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.cts.authorization.model.User;
import com.cts.authorization.repository.UserDao;

@SpringBootTest
class JwtUserDetailsServiceTest {
	
	@Mock
	private UserDao userDao;

	@Mock
	private PasswordEncoder bcryptEncoder;

	@InjectMocks
	private JwtUserDetailsService service;
	
	
	@BeforeEach
	void setUp() throws Exception {
	}

	@Test
	void loadUserByUserNameShouldThrowExceptionTest() {
		when(userDao.findByUserName("invalidUserName")).thenReturn(null);
		assertThatThrownBy(() -> service.loadUserByUsername("invalidUserName")) 
        .isInstanceOf(UsernameNotFoundException.class)
        .hasMessage("User not found with username: invalidUserName");
		verify(userDao, Mockito.times(1)).findByUserName("invalidUserName");
	}
	
	@Test
	void loadUserByUserNameShouldUserNameTest() {
		when(userDao.findByUserName("username")).thenReturn(new User(1,"username","pass"));
		assertThat(service.loadUserByUsername("username")).isNotNull();
		verify(userDao, Mockito.times(1)).findByUserName("username");
	}

}
