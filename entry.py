import tkinter as tk
from projet import *
import tkinter.messagebox
from tkinter import filedialog as fd
import random
from tkinter import ttk

window = tk.Tk()
mystring =tk.StringVar(window)
window.geometry("500x500")
window['background']='#E0E0FF'
window.title("Flow graph")


def filereader ():
    file = ('text files', '*.txt'),('All files', '*.*')
    filepath = fd.askopenfilename(filetypes=file)
    if readFile(filepath) == False :

         #print("errroooor dans la trame")
        tk.messagebox.showinfo("Error","We didn't detect trame in your file\n\n Make sur you have choosed the right text file")

    else :
        dic = readFile(filepath)
        affichage(dic)


welcome_label = tk.Label(text="Welcome in \n Flow graph program",font=("Aria", 16),bg='#E0E0FF').pack(padx=50 ,pady=40)
submit = tk.Button(window, height=3 , width=30,
                text ='Select your text trace file',font="Input",
                fg ='White', 
                bg = '#45458B', command = filereader).pack(padx=50,pady=20)


exit_button = tk.Button(window,height=2 , width=5,text='Exit',command=lambda: window.quit()).pack(padx=50,pady=40)


def affichage(dic):    
    
    
    def selected(event):
        r = w.get()
        if r == 'TCP':
            afficheronlytcp()
        elif r == 'HTTP':
            afficheronlyhttp()
        elif r == 'TCP/HTTP':
            affichagedestrames(dic)

    root = tk.Tk()
    root.title('Flow graph')
    root.geometry("1200x700")
    root['background'] = '#535386'

    frame2 = tk.Frame(root)
    frame2.pack(side="bottom",pady=80)
    space = tk.Label(frame2, text="    Filter   :    ",font=("Helvetica", 14))
    space.pack(side="left")

    choices = ['TCP/HTTP', 'TCP', 'HTTP']
    clicked = tk.StringVar()
    w = ttk.Combobox(frame2, value=choices)
    w.current(0)
    w.bind("<<ComboboxSelected>>", selected)
    w.pack(side="left")


    my_frame = tk.Frame(root)
    my_frame.pack(side="top", pady=30)
    my_frame['background'] =  '#535386'


    txt = tk.Label(my_frame, bg='#535386',fg="white",text="                             Flow graph                                                                                            Comment                            ",font=("Helvetica", 18))
    txt.pack()

    flow_scroll = tk.Scrollbar(my_frame)
    flow_scroll.pack(side = tk.RIGHT, fill = tk.Y)

    width_scroll = tk.Scrollbar(my_frame, orient='horizontal')
    width_scroll.pack(side=tk.BOTTOM, fill=tk.X,pady=0)

    commentaire = tk.Text(my_frame, width=40, height=50, font=("Helvetica", 12), yscrollcommand=flow_scroll.set,xscrollcommand=width_scroll.set, wrap="none")
    commentaire.pack(side="right",padx=40,pady=20)


    flow_graph = tk.Text(my_frame, width=80, height=50, font=("Helvetica", 12), yscrollcommand=flow_scroll.set,xscrollcommand=width_scroll.set, wrap="none")
    flow_graph.pack(side="left",padx=40,pady=20)

    def multiple_yview1(*args):
        flow_graph.yview(*args)
        commentaire.yview(*args)
    def multiple_yview(*args):
        flow_graph.xview(*args)
        commentaire.xview(*args)

    flow_scroll.config(command=multiple_yview1)
    width_scroll.config(command=multiple_yview)


  

    liste_couleurs = []
    base = "nom"
    col = 0
    for i in dic:  # i est une trame
        if "ip" in dic[i] and len(dic[i]["ip"]) != 0:
            if len(liste_couleurs) == 0:
                color = '#' + ("%06x" % random.randint(0, 16777215))
                flow_graph.tag_configure(base + str(i), foreground=color)
                liste_couleurs.append([dic[i]["ip"]['source'], dic[i]["ip"]["destination"], base + str(i)])

            col = 0  # initialise la couleur qu'on va récupérer
            for j in range(len(liste_couleurs)):

                if dic[i]["ip"]["source"] in liste_couleurs[j] and dic[i]["ip"]["destination"] in liste_couleurs[j]:
                    col = liste_couleurs[j][2]  # récupère la couleur associée à cette couple
                    break
                else:
                    if j == len(
                            liste_couleurs) - 1:  # si à la fin de boucle on n'a pas pu récupérer une couleur, alors on ajoute les ip dans la liste_couleurs
                        color = '#' + ("%06x" % random.randint(0, 16777215))
                        flow_graph.tag_configure(base + str(i), foreground=color)
                        liste_couleurs.append([dic[i]["ip"]["source"], dic[i]["ip"]["destination"], base + str(i)])

   
    def flowgraph_insert(ipsrc, ipsend, affich, comment):
        for i in range(len(liste_couleurs)):
            #print(i)
            if ipsrc in liste_couleurs[i] and ipsend in liste_couleurs[i]:
                #print(liste_couleurs[i][0])
                #print(liste_couleurs[i][1])
                break

        flow_graph.insert(0.2, affich + "\n\n", liste_couleurs[i][2])
        commentaire.insert(0.2, comment + "\n\n")
        

    def TCPcomment(liste):
        res = "Seq=" + liste["seq"] 
        res += " Ack=" + liste["ACK_num"] if liste["ACK_num"] != 0 else ""
        res += " Win=" + liste["window"] # LEN?????
        #print("here", res)

        if len(liste["options"]) > 0:
            for op in liste["options"].keys():
                if op not in ["NOP", "EOL"]:
                    if op == "TS":
                        res += " TSval=" + liste["options"][op]["TSval"] + " TSecr=" + liste["options"][op]["TSecr"]
                    else:
                        res += " " + op
                        res += "=" + liste["options"][op]["value"] if liste["options"][op]["value"] != "" else ""
        
        #print(maliste[i][2])
        return res

    source_sender = []
    def affichagedestrames(liste):
        flow_graph.delete(1.0, tk.END)
        commentaire.delete(1.0,tk.END)

        send = '>>>   '
        recieve = '  <<<'
        ligne = ' ====== '

        i = len(liste)

        while i > 0:

            if "ip" in liste[i].keys() and len(liste[i]["ip"]) != 0:
                ip_src = liste[i]["ip"]["source"]
                ip_dest = liste[i]["ip"]["destination"]

            operation = ""
            comment = ""
            affichage= ""


            if "tcp" in liste[i].keys() and len(liste[i]["tcp"]) != 0:
                src_port = liste[i]["tcp"]["source port"]
                dest_port = liste[i]["tcp"]["dest port"]
                    #print(liste[i]["tcp"])

                if liste[i]["tcp"]["ack"] == '1': operation += 'ACK '
                if liste[i]["tcp"]["psh"] == '1': operation += 'PUSH '
                if liste[i]["tcp"]["rst"] == '1': operation += 'RST '
                if liste[i]["tcp"]["syn"] == '1': operation += 'SYN '
                if liste[i]["tcp"]["fin"] == '1': operation += 'FIN '
                    # print(operation)
                operation = "[" + operation.strip().replace(" ", ", ") + "]"
                comment = TCPcomment(liste[i]["tcp"])
                        
                if ip_dest in source_sender:
                    affichage = "[" + ip_dest + "]  " + str(dest_port) + recieve + ligne + operation + ligne + str(
                                src_port) + "  [" + ip_src + "]"

                else:
                    if ip_src not in source_sender :
                                source_sender.append(ip_src)
                    affichage = "[" + ip_src + "]  " + str(src_port) + ligne + operation + ligne + send + str(
                                dest_port) + "  [" + ip_dest + "]"
            if "http" in liste[i].keys() and len(liste[i]["http"]) != 0:
                if ip_src in source_sender:
                    affichage = "[" + ip_src + "]  " + str(src_port) + ligne + str(liste[i]["http"]["header"]) + ligne + send + str(dest_port) + "  [" + ip_dest + "]"

                elif ip_dest in source_sender:
                    affichage = "[" + ip_dest + "]  " + str(dest_port) + recieve +ligne + str(liste[i]["http"]["header"]) + ligne + str(src_port) + "  [" + ip_src + "]"
                # else :
                #     affichage = "  [" + ip_src + "]  " + str(src_port) + ligne + str(liste[i]["http"]["header"]) + ligne + send + str(dest_port) + "  [" + ip_dest + "]"
                comment = ""
                comment = " request " +"Host=" + liste[i]["http"]["Host"] if liste[i]["http"]["isrequete"] else "response"
                comment += " Content-Type=" + liste[i]["http"]["Content-Type"]
            flowgraph_insert(ip_src, ip_dest,str(i)+". "+affichage,str(i)+". "+comment)
            i-=1
            

    liste = dic
    def afficheronlytcp() :
        source_sender = []

        flow_graph.delete(1.0, tk.END)
        commentaire.delete(1.0,tk.END)

        send = '>>>   '
        recieve = '  <<<'
        ligne = ' ====== '

        i = len(liste)

        while i > 0:
            if "ip" in liste[i].keys() and len(liste[i]["ip"]) != 0:
                ip_src = liste[i]["ip"]["source"]
                ip_dest = liste[i]["ip"]["destination"]

            operation =' '
            comment = ""


            if "tcp" in liste[i].keys() and len(liste[i]["tcp"]) != 0:
                src_port = liste[i]["tcp"]["source port"]
                dest_port = liste[i]["tcp"]["dest port"]
                    #print(liste[i]["tcp"])
                if liste[i]["tcp"]["ack"] == '1': operation += 'ACK '
                if liste[i]["tcp"]["psh"] == '1': operation += 'PUSH '
                if liste[i]["tcp"]["rst"] == '1': operation += 'RST '
                if liste[i]["tcp"]["syn"] == '1': operation += 'SYN '
                if liste[i]["tcp"]["fin"] == '1': operation += 'FIN '
                    # print(operation)
                operation = "[" + operation.strip().replace(" ", ", ") + "]"
                comment = TCPcomment(liste[i]["tcp"])
                        
                if ip_dest in source_sender:
                    affichage = "[" + ip_dest + "]  " + str(dest_port) + recieve + ligne + operation + ligne + str(
                                src_port) + "  [" + ip_src + "]"

                else:
                    if ip_src not in source_sender:
                                source_sender.append(ip_src)
                    affichage = "[" + ip_src + "]  " + str(src_port) + ligne + operation + ligne + send + str(
                                dest_port) + "  [" + ip_dest + "]"

           
            flowgraph_insert(ip_src, ip_dest,str(i)+". "+affichage,str(i)+". "+comment)
            i-=1


    def afficheronlyhttp():
        source_sender = []

        flow_graph.delete(1.0, tk.END)
        commentaire.delete(1.0,tk.END)

        send = '>>>   '
        recieve = '  <<<'
        ligne = ' ====== '

        i = len(liste)

        while i > 0:
            commentHTTP = ""
            affichageHTTP = ""
            if "ip" in liste[i].keys() and len(liste[i]["ip"]) != 0:
                ip_src = liste[i]["ip"]["source"]
                ip_dest = liste[i]["ip"]["destination"]

            if "tcp" in liste[i].keys() and len(liste[i]["tcp"]) != 0:
                if len(liste[i]["tcp"]) != 0:
                    src_port = liste[i]["tcp"]["source port"]
                    dest_port = liste[i]["tcp"]["dest port"]
                        
            if ip_dest in source_sender: z=1

            else:
                if ip_src not in source_sender :
                            source_sender.append(ip_src)
    

            if "http" in liste[i].keys() and len(liste[i]["http"]) != 0:
        
                if ip_src in source_sender:
                    affichageHTTP = "[" + ip_src + "]  " + str(src_port) + ligne + str(liste[i]["http"]["header"]) + ligne + send + str(dest_port) + "  [" + ip_dest + "]"

                elif ip_dest in source_sender:
                    affichageHTTP = "[" + ip_dest + "]  " + str(dest_port) + recieve +ligne + str(liste[i]["http"]["header"]) + ligne + str(src_port) + "  [" + ip_src + "]"
                # else :
                #     affichageHTTP = "  [" + ip_src + "]  " + str(src_port) + ligne + str(liste[i]["http"]["header"]) + ligne + send + str(dest_port) + "  [" + ip_dest + "]"
                #print(affichageHTTP)
                commentHTTP = ""
                commentHTTP = " request " +"Host=" + liste[i]["http"]["Host"] if liste[i]["http"]["isrequete"] else "response"
                commentHTTP += " Content-Type=" + liste[i]["http"]["Content-Type"]
                flowgraph_insert(ip_src, ip_dest, str(i)+". "+affichageHTTP,str(i)+". "+commentHTTP)
            i-=1
    affichagedestrames(dic)

    

    root.mainloop()

window.mainloop()