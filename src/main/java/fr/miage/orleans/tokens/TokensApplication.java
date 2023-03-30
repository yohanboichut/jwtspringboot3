package fr.miage.orleans.tokens;

import fr.miage.orleans.tokens.facades.Facade;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class TokensApplication {

    public static void main(String[] args) {
        SpringApplication.run(TokensApplication.class, args);
    }


    @Bean
    public CommandLineRunner commandLineRunner(Facade facade, PasswordEncoder passwordEncoder) {
        return args -> {
            facade.enregistrerAdmin("admin@admin.org","Super", "Admin", passwordEncoder.encode("admin"));
        };
    }

}
