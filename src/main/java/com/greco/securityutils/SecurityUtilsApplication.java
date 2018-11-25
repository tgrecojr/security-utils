package com.greco.securityutils;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

@Slf4j
@SpringBootApplication
public class SecurityUtilsApplication {

    public static void main(String[] args) {

        SpringApplication.run(SecurityUtilsApplication.class, args);
    }

    @Bean
    ApplicationRunner init() {
        return args -> {
            Security.addProvider(new BouncyCastleProvider());
            int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
            log.info("Max Key Size for AES : " + maxKeySize);
            if(maxKeySize == 128){
                log.error("SHUTTING DOWN: EXPORT CRYPTO NOT FOUND.  PLEASE INSTALL JCE POLICIES");
                System.exit(-1);
            }
            Provider p[] = Security.getProviders();
            for (int i = 0; i < p.length; i++) {
                for (Enumeration e = p[i].keys(); e.hasMoreElements();)
                    log.info(p[i] + " - " +  e.nextElement());
            }
        };
    }
}
