package com.infinity.service;

import java.util.List;

import com.infinity.model.User;
import com.infinity.model.UserDto;

public interface UserService {

    User save(UserDto user);
    List<User> findAll();
    void delete(long id);
    User findOne(String username);

    User findById(Long id);
}
