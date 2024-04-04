package fr.miage.orleans.tokens.controleur;

import fr.miage.orleans.tokens.facades.EmailDejaPrisException;
import fr.miage.orleans.tokens.facades.Facade;
import fr.miage.orleans.tokens.facades.Personne;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.security.Principal;
import java.util.Optional;
import java.util.function.Function;

@RestController
@EnableWebSecurity
@RequestMapping("/api")
public class Controleur {

    private static final String TOKEN_PREFIX="Bearer ";
    Facade facade;
    PasswordEncoder passwordEncoder;
    Function<Personne,String> genereToken;
    public Controleur(Facade facade, PasswordEncoder passwordEncoder, Function<Personne,String> genereToken) {
        this.facade = facade;
        this.passwordEncoder = passwordEncoder;
        this.genereToken=genereToken;
    }





    @PostMapping("/register")
    public ResponseEntity<String> enregistrer(@RequestParam String email, @RequestParam String nom, @RequestParam String prenom, @RequestParam String password){
        try {
            facade.enregistrerPersonne(email, nom, prenom, passwordEncoder.encode(password));
            Personne j = facade.getPersonneById(email).get();
            return ResponseEntity.status(HttpStatus.CREATED).header(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX+genereToken.apply(j)).build();
        }
        catch (EmailDejaPrisException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
    }


    @PostMapping("/login")
    public ResponseEntity login( @RequestBody Personne personne) {
        Optional<Personne> oj = facade.getPersonneById(personne.email());

        if (oj.isEmpty())
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

        Personne j = oj.get();
        if (passwordEncoder.matches(personne.password(), j.password())) {
            String token = genereToken.apply(j);
            return ResponseEntity.status(HttpStatus.CREATED).header(HttpHeaders.AUTHORIZATION,TOKEN_PREFIX+token).build();
        };
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }



    @GetMapping("/admin")
    public ResponseEntity<String> yeah(Principal principal){
        return ResponseEntity.ok("Yeahhh ! salut l'admin "+ principal.getName());
    }


    @GetMapping("/user")
    public ResponseEntity<String> yeahUser(Principal principal){
        return ResponseEntity.ok("Yeahhh ! salut le user "+ principal.getName());
    }

}
