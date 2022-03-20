package com.scalablescripts.auth.data;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepo extends CrudRepository<User, Long> {
    Optional<User> findByEmail(String email);

    @Query("""
            select u.* from user u inner join token t on u.id = t.user
            where u.id = :id and t.refresh_token = :refreshToken and t.expired_at >= :expiredAt
            """)
    Optional<User> findByIdAndTokensRefreshTokenAndTokensExpiredAtGreaterThan(Long id, String refreshToken, LocalDateTime expiredAt);
}
