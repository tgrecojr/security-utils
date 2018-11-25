package com.greco.securityutils.bus;

import com.google.common.primitives.Chars;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.RandomStringGenerator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

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
    private static int DEFAULT_NUMBER_OF_PASSWORDS = 1;


    @GetMapping("/pwgen")
    private List generatePassword(@RequestParam(required = false, defaultValue = "1") int number,@RequestParam Optional<String> type, @RequestParam int passwordLength) throws Exception{

        SecureRandom random = SecureRandom.getInstanceStrong();
        List<String> passwordArray = new ArrayList();
        IntStream.range(0, number).forEach(
                nbr -> passwordArray.add(getPassword(random,type,passwordLength))) ;
        return passwordArray;

    }

    private  String  getPassword(SecureRandom random,Optional type,int passwordLength){

        RandomStringGenerator generator = new RandomStringGenerator.Builder()
                .selectFrom(getAllowedValues(type))
                .usingRandom(random::nextInt)
                .build();
        return generator.generate(passwordLength);
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
