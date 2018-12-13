package com.greco.securityutils.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class ErrorDetails {

    @NonNull
    private Date timestamp;
    @NonNull
    private String message;
    @NonNull
    private String details;


}
