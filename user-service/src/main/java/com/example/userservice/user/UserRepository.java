package com.example.userservice.user;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    String SEARCH = """
            from UserEntity u
            where :q = ''
               or u.username like :pattern escape '\\'
               or u.email like :pattern escape '\\'
               or lower(u.firstName) like :pattern escape '\\'
               or lower(u.lastName) like :pattern escape '\\'
            """;

    Optional<UserEntity> findByUsername(String username);

    Optional<UserEntity> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query(value = "select u " + SEARCH + " order by u.username", countQuery = "select count(u) " + SEARCH)
    Page<UserEntity> search(@Param("q") String q, @Param("pattern") String pattern, Pageable pageable);

    @Query("select count(u) " + SEARCH)
    long countSearch(@Param("q") String q, @Param("pattern") String pattern);

    /** Offset-based variant for the Keycloak SPI (first/max need not align with pages). */
    @Query("select u " + SEARCH + " order by u.username offset :first rows fetch first :max rows only")
    List<UserEntity> searchSlice(@Param("q") String q, @Param("pattern") String pattern,
                                 @Param("first") int first, @Param("max") int max);
}
