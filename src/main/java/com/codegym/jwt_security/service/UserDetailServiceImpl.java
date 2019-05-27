package com.codegym.jwt_security.service;

import com.codegym.jwt_security.model.User;
import com.codegym.jwt_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user=userRepository.findByUsername(s);
        if(user==null) {
            throw new UsernameNotFoundException("User not found");
        }
        String name=user.getUsername();
        String password=user.getPassword();
        Set<GrantedAuthority> grantedAuthoritySet=new HashSet<>();
        grantedAuthoritySet.add(new SimpleGrantedAuthority(user.getRole()));
        return new org.springframework.security.core.userdetails.User(name,password,grantedAuthoritySet);
    }
}
