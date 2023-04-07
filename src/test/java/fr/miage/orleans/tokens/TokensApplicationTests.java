package fr.miage.orleans.tokens;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@SpringBootTest
@AutoConfigureMockMvc
class TokensApplicationTests {


    @Autowired
    MockMvc mvc;


    @MockBean
    Facade facade;

    @MockBean
    PasswordEncoder passwordEncoder;



    @Autowired
    ObjectMapper objectMapper;



    @Autowired
    Function<Personne,String> genereToken;


    @Test
    public void testEnregistrerPersonne1() throws Exception {

        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";
        Role[] roles = new Role[]{Role.USER};

        doReturn(passwordEncode).when(passwordEncoder).encode(password);
        Personne personne = new Personne(email,nom,prenom,passwordEncode,roles);
        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);


        mvc.perform(post(URI.create("/api/register")).contentType(MediaType.APPLICATION_FORM_URLENCODED).content("email="+email+"&nom="+nom+"&prenom="+prenom+"&password="+password))
                .andExpect(status().isCreated());
    }



    @Test
    public void testEnregistrerPersonne2() throws Exception {

        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";


        doReturn(passwordEncode).when(passwordEncoder).encode(password);
        doThrow(EmailDejaPrisException.class).when(facade).enregistrerPersonne(email,nom,prenom,passwordEncode);


        mvc.perform(post(URI.create("/api/register")).contentType(MediaType.APPLICATION_FORM_URLENCODED).content("email="+email+"&nom="+nom+"&prenom="+prenom+"&password="+password))
                .andExpect(status().isConflict());
    }




    @Test
    public void testLogin1() throws Exception {
        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";
        Role[] roles = new Role[]{Role.USER};
        Personne personne = new Personne(email,nom,prenom,passwordEncode,roles);
        Personne personneEnvoyee = new Personne(email,nom,prenom,password,roles);

        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);
        doReturn(true).when(passwordEncoder).matches(password,passwordEncode);

        mvc.perform(post(URI.create("/api/login")).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(personneEnvoyee)))
                .andExpect(status().isCreated());

    }



    @Test
    public void testLogin2() throws Exception {
        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        Role[] roles = new Role[]{Role.USER};

        Personne personneEnvoyee = new Personne(email,nom,prenom,password,roles);

        doReturn(Optional.empty()).when(facade).getPersonneById(email);
        mvc.perform(post(URI.create("/api/login")).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(personneEnvoyee)))
                .andExpect(status().isForbidden());
    }


    // on active le second FORBIDDEN
    @Test
    public void testLogin3() throws Exception {
        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";
        Role[] roles = new Role[]{Role.USER};
        Personne personne = new Personne(email,nom,prenom,passwordEncode,roles);
        Personne personneEnvoyee = new Personne(email,nom,prenom,password,roles);

        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);
        doReturn(false).when(passwordEncoder).matches(password,passwordEncode);

        mvc.perform(post(URI.create("/api/login")).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(personneEnvoyee)))
                .andExpect(status().isForbidden());
    }



    @Test
    public void testYeah() throws Exception {

        // On a besoin de récupérer un token pour l'authentification
        // Notre utilisateur doit être ADMIN

        String email = "yohan.boichut@univ-orleans.fr";
        String nom = "Boichut";
        String prenom = "Yohan";
        String password = "babar";
        String passwordEncode = "celestine";
        Role[] roles = new Role[]{Role.ADMIN};
        Personne personne = new Personne(email, nom, prenom, passwordEncode, roles);
        Personne personneEnvoyee = new Personne(email, nom, prenom, password, roles);

        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);
        doReturn(true).when(passwordEncoder).matches(password, passwordEncode);



        // On utilise le générateur de token pour créer des tokens valides
        String myToken = "Bearer "+genereToken.apply(personne);



        // Test de la fonctionnalité /admin

        mvc.perform(get(URI.create("/api/admin")).header("Authorization",myToken))
                .andExpect(status().isOk());


    }




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
        Personne personneEnvoyee = new Personne(email, nom, prenom, password, roles);

        doReturn(Optional.of(personne)).when(facade).getPersonneById(email);
        doReturn(true).when(passwordEncoder).matches(password, passwordEncode);


        // On utilise le générateur de token pour créer des tokens valides
        String myToken = "Bearer "+genereToken.apply(personne);



        // Test de la fonctionnalité /admin

        mvc.perform(get(URI.create("/api/user")).header("Authorization",myToken))
                .andExpect(status().isOk());


    }




}
