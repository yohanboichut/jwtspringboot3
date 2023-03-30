package fr.miage.orleans.tokens.facades;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class Facade {

    Map<String,Personne> personnesMap;


    public Facade() {
        this.personnesMap = new HashMap<>();
    }


    public void enregistrerPersonne(String email, String nom, String prenom, String motDePasse) throws EmailDejaPrisException {
        if (personnesMap.containsKey(email))
            throw new EmailDejaPrisException();
        this.personnesMap.put(email,new Personne(email,nom,prenom,motDePasse,new Role[]{Role.USER}));
    }


    public Optional<Personne> getPersonneById(String email) {
        if (this.personnesMap.containsKey(email))
            return Optional.of(this.personnesMap.get(email));
        else
            return Optional.empty();
    }

    public void enregistrerAdmin(String adminEmail, String adminNom, String adminPrenom, String adminMDP) {
        this.personnesMap.put(adminEmail,new Personne(adminEmail,adminNom,adminPrenom,adminMDP,new Role[]{Role.ADMIN,Role.USER}));
    }
}
