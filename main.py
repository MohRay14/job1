import re

def is_valid_password(password):
    # Vérification de la longueur
    if len(password) <= 8:
        return False, "Le mot de passe doit contenir plus de 8 caractères."

    # Lettre minuscule
    if not re.search(r"[a-z]", password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule."

    # Lettre majuscule
    if not re.search(r"[A-Z]", password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."

    # Chiffre
    if not re.search(r"[0-9]", password):
        return False, "Le mot de passe doit contenir au moins un chiffre."

    # Caractère spécial
    if not re.search(r"[_@$]", password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial (_ @ $)."

    # Pas d'espace
    if re.search(r"\s", password):
        return False, "Le mot de passe ne doit pas contenir d'espace."

    # Si toutes les conditions sont remplies
    return True, "Mot de passe valide ✔️"


# Exemple d'utilisation :
password = "R@m@_f0rtu9e$"
valid, message = is_valid_password(password)
print(message)


import tkinter as tk
from tkinter import messagebox
import re

def is_valid_password(password):
    if len(password) <= 8:
        return False, "Le mot de passe doit contenir plus de 8 caractères."
    if not re.search(r"[a-z]", password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule."
    if not re.search(r"[A-Z]", password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule."
    if not re.search(r"[0-9]", password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[_@$]", password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial (_ @ $)."
    if re.search(r"\s", password):
        return False, "Le mot de passe ne doit pas contenir d'espace."
    return True, "Mot de passe valide ✔️"

def check_password():
    password = entry.get()
    valid, message = is_valid_password(password)
    if valid:
        messagebox.showinfo("Résultat", message)
    else:
        messagebox.showerror("Erreur", message)

# --- Interface Tkinter ---

root = tk.Tk()
root.title("Vérification de mot de passe")
root.geometry("350x200")
root.resizable(False, False)

label = tk.Label(root, text="Entrez un mot de passe :", font=("Arial", 12))
label.pack(pady=10)

entry = tk.Entry(root, show="*", font=("Arial", 12), width=25)
entry.pack()

button = tk.Button(root, text="Vérifier", command=check_password, font=("Arial", 12))
button.pack(pady=20)

root.mainloop()
