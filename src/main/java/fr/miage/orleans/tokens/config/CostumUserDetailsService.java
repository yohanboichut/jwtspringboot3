package fr.miage.orleans.tokens.config;

import fr.miage.orleans.tokens.facades.Facade;
import fr.miage.orleans.tokens.facades.Personne;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

public class CostumUserDetailsService implements UserDetailsService {
    private static final String[] ROLES_ADMIN = {"USER","ADMIN"};
    private static final String[] NO_ROLE={};

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
        String[] roles = NO_ROLE;
        UserDetails userDetails = User.builder()
                .username(utilisateur.email())
                .password(passwordEncoder.encode(utilisateur.password()))
                .roles(roles)
                .authorities(roles)
                .build();
        return userDetails;
    }
}
