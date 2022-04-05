package com.csrf.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    @Autowired
    private UserRepo userRepo;


    @Transactional
    public Integer updateUserCredUsingUsername(String userName){
        System.out.println("Updating password for user: " + userName);
        //Validating user using username/csrf token
        Integer success = userRepo.updateUserPasswordByUserName(userName, "mypassword");
        if(success==1){
            System.out.println("Password updated successfully for user: " + userName);
        } else {
            System.out.println("Not able to update password :(");
        }
        return success;
    }

    public int checkLogin(String username, String password) {
        System.out.println("Checking login for user: " + username);
        User user = userRepo.findByUserName(username);
        if(user == null){
            return -1;
        }
        if(password.equals(user.getPassword())){
            return 1;
        }
        return 0;
    }

    public User getUserByUsername(String username) {
        return userRepo.findByUserName(username);
    }
}
