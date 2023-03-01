erreurs = []

def readFile(filename):
    try :
        f = open(filename, "r")
    except :
        return False
    lignes = f.readlines()
    liste_octets = []
    for ligne in lignes:
        liste_octets.append(ligne.strip().lower())  # separates one element
    res = sortOut(liste_octets)
    return res if res else False

def sortOut(liste_octets):
    liste_finale = []
    liste_temporaire = []
    ok = False
    # suppression de listes vides
    liste_octets = [x for x in liste_octets if x]

    for i in range(len(liste_octets)):

        ligne = liste_octets[i].split()
        if ligne[0] == '0000':
            if ok:
                liste_finale.append(liste_temporaire)
                liste_temporaire = []
            ok = True

        for element in range(len(ligne)):
            try:
                # n'entre pas dans la boucle pour 0
                if int(ligne[element], 16) == 0 or int(ligne[element], 16):
                    liste_temporaire.append(ligne[element])
            except:
                break
        if i == len(liste_octets) - 1:
            liste_finale.append(liste_temporaire)

    return verifieSequence(liste_finale)

def verifieSequence(list):
    global erreurs
    nb_couple = 0
    seq_courante = 0
    liste_temporaire = []
    liste_finale = []
    trame_erronee = {}

    for i in range(len(list)):
        nb_couple = 0
        seq_courante = 0
        liste_temporaire = []

        for j in range(len(list[i])):

            if len(list[i][j]) == 4:
                if seq_courante != 0:
                    if nb_couple < int(list[i][j], 16) - seq_courante:
                        # si list[i][j] est dans la partie des caractères et qu'il a été pris par faut
                        if j+1 < len(list[i]) and len(list[i][j+1]) == 4:
                            if nb_couple == int(list[i][j+1], 16) - seq_courante:
                                continue

                        else:
                            # print(type(i))
                            tmp = "trame numéro ", str(i+1), " est erronée"
                            erreurs.append(tmp)
                            #print(nb_couple, list[i][j],list[i][j+1], seq_courante)
                            trame_erronee[i+1] = list[i]
                            break
                seq_courante = int(list[i][j], 16)
                nb_couple = 0
            elif len(list[i][j]) == 2:
                liste_temporaire.append(list[i][j])
                nb_couple += 1

            if j == len(list[i]) - 1:
                liste_temporaire.append(list[i][j])

        if i+1 not in trame_erronee.keys():
            liste_finale.append(liste_temporaire)

    return analyse(liste_finale)


def analyse(trames):
    global erreurs
    res = {}
    eth = {}
    ip = {}
    tcp = {}
    http = {}

    for i in range(len(trames)):
        var = ethernet(trames[i])
        #print("var", var)
        if var == None:
            tmp = "trame numéro ", str(i+1), " est erronée"
            erreurs.append(tmp)
        else:
            eth, ip, tcp, http = ethernet(trames[i])
            res[i+1] = {"ethernet": eth, "ip": ip, "tcp": tcp, "http": http}
    return res


def ethernet(trame):

    res_dic = {}
    ip = {}
    tcp = {}
    http = {}
    if len(trame) >= 14 : 
        res_dic["dest_mac"] = ":".join(trame[0:6])
        res_dic["src_mac"] = ":".join(trame[6:12])
        res_dic["type"] = trame[12] + trame[13]

        if res_dic["type"] == '0800' and len(trame) > 15:
            ip, tcp, http = ipv4(trame[14:])

        res_dic["type"] = "0x" + res_dic["type"]

    return res_dic, ip, tcp, http


def ipv4(trame):

    offset = 0
    res_dic = {}
    tcp = {}
    http = {}
     #print(trame)
    if len(trame) >= 20:
        res_dic["version"] = trame[0][0]
        res_dic["ihl"] = str(int(trame[0][1], 16))
        res_dic["protocol"] = trame[9]
        res_dic["source"] = ".".join([str(int(x, 16))
                                    for x in trame[12:16]])
        res_dic["destination"] = ".".join(
            [str(int(x, 16)) for x in trame[16:20]])

        if int(res_dic["ihl"]) < 5:
            return
            #print("Erreur, l'entête IP doit avoir au moins 20 octets")

        else:
            res_dic["tos"] = str(int(trame[1], 16)) # valuer? 
            res_dic["thl"] = str(int(trame[2] + trame[3], 16))
    
            if res_dic["protocol"] == "06" and len(trame) > 21:
                tcp, http = TCP(trame[20:])  # rend res_dic, http

    return res_dic, tcp, http


def TCP(trame):
    res_dic = {}
    offset = 0
    if len(trame) >= 20:
        res_dic["source port"] = str(int("".join(trame[0:2]), 16))
        res_dic["dest port"] = str(int("".join(trame[2:4]), 16))

        res_dic["seq"] = str(int("".join(trame[4:8]), 16))
        res_dic["ACK_num"] = str(int("".join(trame[8:12]), 16))
        # Header Length, sur 4 bits
        res_dic["Data_offset"] = str(int(trame[12][0], 16))

        index_13_0 = int(trame[13][0], 16)
        index_13_1 = int(trame[13][1], 16)

        Reserved = bin(int(trame[12][1], 16))[2:] + "0" if index_13_0 & 8 == 0 else "1"  # 4 bits restants + 2 bits (du poids fort)
        Reserved += "0" if index_13_0 & 4 == 0 else "1"
        res_dic["reserved"] = Reserved
        res_dic["urg"] = '0' if index_13_0 & 2 == 0 else '1'
        res_dic["ack"] = '0' if index_13_0 & 1 == 0 else '1'
        res_dic["psh"] = '0' if index_13_1 & 8 == 0 else '1'
        res_dic["rst"] = '0' if index_13_1 & 4 == 0 else '1'
        res_dic["syn"] = '0' if index_13_1 & 2 == 0 else '1'
        res_dic["fin"] = '0' if index_13_1 & 1 == 0 else '1'

        res_dic["window"] = str(int("".join(trame[14:16]), 16))
        res_dic["checksum"] = "".join(trame[16:18])
        res_dic["Urgent_pointer"] = str(int(trame[18] + trame[19], 16))

        if int(res_dic["Data_offset"]) < 5:
            #print("erreur, Data Offset is less than 5 words (20 bytes)")
            return

        elif int(res_dic["Data_offset"]) > 15:
            #print("erreur, Data Offset is greater than 15 words (60 bytes)")
            return

        else:
            options = {}
            debut_options = int(res_dic["Data_offset"]) * 4 - 20
            i = 0
            while debut_options > 0: # amélioration des cas, quel options peuvent ne pas avoir de valeur ??? 
                index = 20 + i
                type_op = int(trame[index], 16)

                if type_op == 0:  # EOL : End of Options List
                    options["EOL"] = {"type": str(type_op)}
                    debut_options -= 1
                    i += 1

                elif type_op == 1:  # NOP : No-Operation
                    options["NOP"] = {"type": str(type_op)}
                    debut_options -= 1
                    i += 1

                elif type_op == 2:  # MSS : Maximum Segment Size
                    length = int(trame[index + 1], 16)
                    value = "".join(trame[index + 2:index + length])
                    value = str(int(value, 16)) if value != "" else ""
                    options["MSS"] = {"type": str(type_op),
                                        "length": str(length), "value": value}
                    debut_options -= length
                    i += length

                elif type_op == 3:  # WScale : Window Scale
                    length = int(trame[index + 1], 16)
                    value = "".join(trame[index + 2:index + length])
                    value = str(pow(2, int(value, 16))) if value != "" else ""
                    options["WScale"] = {
                            "type": str(type_op), "length": str(length), "value": value}

                    debut_options -= length
                    i += length

                elif type_op == 4:  # SACK Permitted
                    length = int(trame[index + 1], 16)
                    value = "".join(trame[index + 2:index + length])
                    value = str(int(value, 16)) if value != "" else ""
                    options["SACK Permitted"] = {
                            "type": str(type_op), "length": str(length), "value": ""}

                    debut_options -= length
                    i += length

                elif type_op == 5:  # Selective ACK
                    length = int(trame[index + 1], 16)
                    value = "".join(trame[index + 2:index + length])
                    value = str(int(value, 16)) if value != "" else ""
                    options["SACK"] = {"type": str(type_op),
                                        "length": str(length), "value": value}

                    debut_options -= length
                    i += length

                elif type_op == 8:  # TS : Timestamp
                    length = int(trame[index + 1], 16)
                    TSval = "".join(trame[index+2:index+length//2+1])
                    TSval = str(int(TSval, 16)) if TSval != "" else ""
                    TSecr = "".join(trame[index+length//2+1:index+length])
                    TSecr = str(int(TSecr, 16)) if TSecr != "" else ""
                    options["TS"] = {"type": str(type_op),
                                        "length": str(length), "TSval": TSval , "TSecr": TSecr }

                    debut_options -= length
                    i += length

                else:
                    #print("TCP option non disponible")
                    debut_options -= 1
                    i += 1

            offset += 20 + i
        res_dic["options"] = options
        http = {}
        # le port 80 => HTTP
        if res_dic["source port"] or res_dic["dest port"] == 80:
            if offset != len(trame) - 1:
                http = HTTP(trame[offset:])
    return res_dic, http


def HTTP(trame):
    http = ""
    # si c'est une requête TRUE, si une réponse FALSE
    requete = True if "".join(trame[:4]) != "48545450" else False
    res = []
    valeurs = []

    for i in range(len(trame)):
        if trame[i] == "20":
            res.append(http)
            http = ""
        elif trame[i-1] == "0d" and trame[i] == "0a":
            res.append(http[:len(http) - 1])
            break
        else:
            http += chr(int(trame[i], 16))

    http = ""
    for i in range(i+1, len(trame)):
        if trame[i] == "20":
            if trame[i-1] == "3a":  # "3a" == ":"
                http = http[:len(http) - 1]
                valeurs.append(http)
                http = ""
            elif trame[i-1] == "3b":
                continue
        elif trame[i-1] == "0d" and trame[i] == "0a":
            if "".join(trame[i-3:i+1]) == "0d0a0d0a":
                break
            valeurs.append(http[:len(http) - 1])
            http = ""
        else:
            http += chr(int(trame[i], 16))

    # Conversion de la liste "valeurs" en dictionnaire "val_dic"
    val_dic = {valeurs[i]: valeurs[i + 1]
               for i in range(0, len(valeurs) - 1, 2)}
    val_dic["header"] = " ".join(res)
    val_dic["isrequete"] = requete

    return val_dic

#print(readFile("trace.txt")[4])