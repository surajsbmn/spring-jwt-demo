package com.surajsbmn.jwtapi.repo;

import com.surajsbmn.jwtapi.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
