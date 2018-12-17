package com.greco.securityutils.data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class PasswordDAO {

    @Autowired
    JdbcTemplate jdbcTemplate;

    String selectSQL = "select password_hash from passwords where password_hash = ?";

    public String getCountForPasswordHash(String theHash){


        String passwordHash = (String) jdbcTemplate.queryForObject(selectSQL, new Object[] { theHash }, String.class);

        return passwordHash;
    }
}
