package fr.miage.orleans.tokens.config;

import fr.miage.orleans.tokens.facades.Facade;
import fr.miage.orleans.tokens.facades.Personne;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class CostumUserDetailsService implements UserDetailsService {

    private PasswordEncoder passwordEncoder;
    private Facade facade;

    public CostumUserDetailsService(PasswordEncoder passwordEncoder, Facade facade) {
        this.passwordEncoder = passwordEncoder;
        this.facade = facade;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Personne> utilisateurOpt = facade.getPersonneById(username);
        if (utilisateurOpt.isEmpty())
            throw new UsernameNotFoundException("User "+username+" not found");

        Personne utilisateur = utilisateurOpt.get();
        List<String> roles = Arrays.stream(utilisateur.roles()).map(x -> x.toString()).collect(Collectors.toList());
        String[] resultat = new String[roles.size()];
        String[] rolesArray = roles.toArray(resultat);
        UserDetails userDetails = User.builder()
                .username(utilisateur.email())
                .password(utilisateur.password())
                .roles(rolesArray)
                .authorities(rolesArray)
                .build();
        return userDetails;
    }
}
