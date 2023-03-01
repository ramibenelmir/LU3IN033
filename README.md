# Analyseur de protocoles

Ce projet est un visualisateur de trafic réseau. 
Le programme prend en entrée un fichier trace (format texte) contenant les octets ‘bruts’, tels que capturés sur le réseau. Il permet de visualiser les différents flux entre les machines.

[Vidéo de présentation](https://youtu.be/mJeHEbMSQY8)

### Contenu de l'archive

Cette archive contient : 
1. Le fichier entry.py et projet.py contiennent le code source du projet.
2. Le fichier howto qui explique comment lancer le programme. 
3. Des fichiers en .txt, qui contiennent des trames à analyser.
4. Une fichier .exe pour faciliter l'exécution de l'application.

### Structure du code

Le code se compose en deux parties : 
- Une partie consacrée à l'extraction des informations pertinentes depuis le fichier texte.
- Une partie pour l'affichage des flux dans l'interface selon les protocols supportés et leurs options. 

#### Partie déchiffrage du fichier texte et analyse : 
- On commence par lire le fichier en entier, et on vérifie si chaque trame est correcte.
- On prend chaque trame, une par une et on les décompose successivement.
- On récupère les informations essentielles de chaque trame selon les protocoles supportés et pour tout organiser en un dictionnaire.

#### Affichage : 
- On crée notre welcome interface, pour récupèrer le fichet .txt de l'utilisateur.
- On récupère le dictionnaire traité par projet.py.
- Visualiser les flux et les adresses ip, les ports et les flags dans la partie "Flow graph", et les options et les valeurs qu'on trouve intéressantes dans la partie "Comment".
- Le filtrage des flux "TCP/HTTP" ou "TCP" ou "HTTP".

### Liste des protocoles analyés :
- Couche 2: Ethernet 
- Couche 3: IP 
- Couche 4: TCP
- Couche 7: HTTP 

## Auteures
Réalisé par : 
- Rami BENELMIR.
- Erisa KOHANSAL.