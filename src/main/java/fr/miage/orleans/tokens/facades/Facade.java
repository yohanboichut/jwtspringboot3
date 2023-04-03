package fr.miage.orleans.tokens.facades;

import java.util.Optional;

public interface Facade {
    void enregistrerPersonne(String email, String nom, String prenom, String motDePasse) throws EmailDejaPrisException;

    Optional<Personne> getPersonneById(String email);

    void enregistrerAdmin(String adminEmail, String adminNom, String adminPrenom, String adminMDP);
}
