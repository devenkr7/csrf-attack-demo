package com.csrf.impl;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserRepo extends JpaRepository<User, Integer> {

    @Modifying
    @Query(nativeQuery = true, value = "UPDATE user SET password = :password WHERE user_name = :username")
    Integer updateUserPasswordByUserName(String username, String password);

    @Query(nativeQuery = true, value = "select * from user where user_name = :username")
    User findByUserName(String username);
}
