package com.greco.securityutils.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.apache.commons.codec.digest.DigestUtils;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Getter
@Setter
@ToString
public class Password {

    private String password;
    private String sha1Hash;
    private boolean owned;

    public Password(String thePassword){
        this.password = thePassword;
        this.sha1Hash = DigestUtils.sha1Hex(thePassword);
    }
}
