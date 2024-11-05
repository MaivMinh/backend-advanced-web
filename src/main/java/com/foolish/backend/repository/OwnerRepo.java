package com.foolish.backend.repository;

import com.foolish.backend.model.Owner;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OwnerRepo extends JpaRepository<Owner, Integer> {
  Owner findById(int id);
}
