package com.greco.securityutils.bus;

import com.google.common.primitives.Chars;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.text.RandomStringGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@RestController
public class PwGenController {

    private static char[]  ALLOWED_VALUES_ALPHABETIC = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z'};

    private static char[]  ALLOWED_VALUES_NUMERIC = { '1','2','3','4','5','6','7','8','9','0'};

    private static char[] ALLOWED_VALUES_SYMBOLS = { '@','%','+','\\','/','\'','!','#','$','^','?',':','.','(',')','{','}','[',']','~','-','_','.'};

    private static String TYPE_ALPHANUMERIC = "alphanumeric";
    private static String TYPE_ALPHABETIC = "alphabetic";


    @GetMapping("/pwgen")
    private String generatePassword(@RequestParam Optional<String> type, @RequestParam int passwordLength) throws Exception{

        SecureRandom random = SecureRandom.getInstanceStrong();
        RandomStringGenerator generator = new RandomStringGenerator.Builder()
                .selectFrom(getAllowedValues(type))
                .usingRandom(random::nextInt)
                .build();
        String randomLetters = generator.generate(passwordLength);
        return randomLetters;

    }

    protected char[] getAllowedValues(Optional<String> passwordType){
        boolean isAlphabetic = passwordType.filter(type -> type.equals(TYPE_ALPHABETIC)).isPresent();
        boolean isAlphaNumeric = passwordType.filter(type -> type.equals(TYPE_ALPHANUMERIC)).isPresent();
        if(isAlphabetic){
            return ALLOWED_VALUES_ALPHABETIC;
        }else if(isAlphaNumeric){
            return Chars.concat(ALLOWED_VALUES_ALPHABETIC, ALLOWED_VALUES_NUMERIC);
        }else{
            return Chars.concat(ALLOWED_VALUES_ALPHABETIC, ALLOWED_VALUES_NUMERIC, ALLOWED_VALUES_SYMBOLS);
        }

    }
}
