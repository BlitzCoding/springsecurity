package yonghlee.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import yonghlee.springsecurity.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
