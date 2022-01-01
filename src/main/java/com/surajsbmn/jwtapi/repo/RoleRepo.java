package com.surajsbmn.jwtapi.repo;

import com.surajsbmn.jwtapi.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
