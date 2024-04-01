package fr.miage.orleans.tokens;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import fr.miage.orleans.tokens.facades.EmailDejaPrisException;
import fr.miage.orleans.tokens.facades.Facade;
import fr.miage.orleans.tokens.facades.Personne;
import fr.miage.orleans.tokens.facades.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.springframework.boot.context.properties.bind.Bindable.mapOf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TokensHugoTests {


    @Autowired
    MockMvc mvc;











    @Test
    public void testYeah() throws Exception {

        // On a besoin de récupérer un token pour l'authentification
        // Notre utilisateur doit être ADMIN

        mvc.perform(get("/api/admin").with(jwt()
                        .authorities(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .jwt(jwt -> jwt.claim(StandardClaimNames.PREFERRED_USERNAME, "yohan.boichut@univ-orleans.fr"))))
                .andExpect(status().isOk());


    }

/*



    @Test
    public void testYeahUser() throws Exception {

        // On a besoin de récupérer un token pour l'authentification
        // Notre utilisateur doit être ADMIN

        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";
        Role[] roles = new Role[]{Role.USER};
        Personne personne = new Personne(email, nom, prenom, passwordEncode, roles);

        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);
        doReturn(true).when(passwordEncoder).matches(password, passwordEncode);


        // On utilise le générateur de token pour créer des tokens valides
        String myToken = "Bearer "+genereToken.apply(personne);



        // Test de la fonctionnalité /admin

        mvc.perform(get(URI.create("/api/user")).header("Authorization",myToken))
                .andExpect(status().isOk());


    }

*/



}
