

---

## **README (English version)**

# DLL Injection in Rust using Windows API

This project demonstrates a **basic DLL injection technique** on Windows, written entirely in **Rust**, using the Windows API.
It uses the well-known `LoadLibraryA` function from `kernel32.dll` to load a DLL into a target process.

---

## **What is DLL Injection?**

DLL injection is a technique where you **force a process to load a Dynamic Link Library (DLL)**, allowing you to execute your own code inside that process.
This can be used for:

* Extending or modifying application behavior.
* Debugging or reverse engineering.
* Creating proof-of-concept security tests.

⚠ **Disclaimer:** This project is for **educational purposes only**. Do not use it on systems you do not own or have permission to test.

---

## **How it Works**

1. **Check if the target process is running**

   * In this example, the target is `notepad.exe`.
   * If it's not running, the program launches it automatically.

2. **Get a handle to the target process**

   * Uses `OpenProcess` with the rights to write memory and create threads.

3. **Get the address of `LoadLibraryA`**

   * From `kernel32.dll` using `GetModuleHandleA` and `GetProcAddress`.

4. **Write the DLL path into the target process's memory**

   * Allocates memory with `VirtualAllocEx`.
   * Writes the DLL path using `WriteProcessMemory`.

5. **Create a remote thread in the target process**

   * Calls `LoadLibraryA` with the DLL path as the argument using `CreateRemoteThread`.

6. **Close all handles**

   * Ensures proper cleanup.

---

## **Code Overview**

Key Windows API calls used:

* `OpenProcess` → Open a process with specific permissions.
* `VirtualAllocEx` → Allocate memory inside another process.
* `WriteProcessMemory` → Write data into another process's memory.
* `GetModuleHandleA` → Get the handle of a loaded DLL.
* `GetProcAddress` → Get the address of a function inside a DLL.
* `CreateRemoteThread` → Run code in another process.

---

## **Requirements**

* **Windows OS** (tested on Windows 10/11)
* **Rust** installed → [Install Rust](https://www.rust-lang.org/tools/install)
* A compiled DLL you want to inject.

---

## **Usage**

1. Clone the repository:

   ```bash
   git clone https://github.com/Psych3-N1x/dll-injection-rust.git
   cd dll-injection-rust
   ```

2. Edit the path to your DLL in `main.rs`:

   ```rust
   let path_to_dll = "C:\\Path\\To\\Your\\dll.dll\0";
   ```

3. Build the project:

   ```bash
   cargo build --release
   ```

4. Run it:

   ```bash
   target\release\dll-injection-rust.exe
   ```

---

## **Example Output**

```
notepad.exe is not running, launching it...
Successfully launched notepad.exe with PID: 1234
[+] Got handle to process ID 1234, handle: 0x000001
[+] Handle to kernel32.dll: 0x00007FF
[+] Address of LoadLibraryA: 0x00007FF
[+] Remote buffer base address: 0x001F0000
[+] Bytes written to remote process: 25
[+] Thread created successfully, handle: 0x000002, thread ID: 5678
[+] DLL injection initiated!
```

---

## **Disclaimer**

This project is **for educational and research purposes only**.
Do **NOT** use it on any system without explicit permission.
The author is **not responsible** for any misuse.

---

### **Version Française (traduction)**

# Injection de DLL en Rust avec l’API Windows

Ce projet démontre une **technique simple d’injection de DLL** sous Windows, entièrement écrite en **Rust**, en utilisant l’API Windows.
Il exploite la fonction `LoadLibraryA` de `kernel32.dll` pour charger une DLL dans un processus cible.

---

## **Qu’est-ce que l’injection DLL ?**

L’injection DLL est une technique qui consiste à **forcer un processus à charger une bibliothèque dynamique (DLL)**, ce qui permet d’exécuter du code à l’intérieur de ce processus.
Applications possibles :

* Étendre ou modifier le comportement d’un programme.
* Débogage ou rétro-ingénierie.
* Création de tests de sécurité à titre de preuve de concept.

⚠ **Avertissement :** Ce projet est uniquement destiné à un usage **éducatif**. N’utilisez pas cette technique sur des systèmes que vous ne possédez pas ou pour lesquels vous n’avez pas d’autorisation.

---

## **Fonctionnement**

1. **Vérifie si le processus cible est en cours d’exécution**

   * Dans cet exemple, la cible est `notepad.exe`.
   * S’il n’est pas lancé, le programme le démarre automatiquement.

2. **Obtention d’un handle vers le processus cible**

   * Utilise `OpenProcess` avec les droits nécessaires pour écrire en mémoire et créer des threads.

3. **Récupération de l’adresse de `LoadLibraryA`**

   * Depuis `kernel32.dll` via `GetModuleHandleA` et `GetProcAddress`.

4. **Écriture du chemin de la DLL dans la mémoire du processus cible**

   * Allocation mémoire avec `VirtualAllocEx`.
   * Écriture du chemin avec `WriteProcessMemory`.

5. **Création d’un thread distant dans le processus cible**

   * Appelle `LoadLibraryA` avec le chemin de la DLL comme argument via `CreateRemoteThread`.

6. **Fermeture des handles**

   * Libère les ressources.

---

## **Aperçu du code**

Appels API Windows principaux :

* `OpenProcess` → Ouvrir un processus avec des droits spécifiques.
* `VirtualAllocEx` → Allouer de la mémoire dans un autre processus.
* `WriteProcessMemory` → Écrire dans la mémoire d’un autre processus.
* `GetModuleHandleA` → Obtenir le handle d’une DLL chargée.
* `GetProcAddress` → Obtenir l’adresse d’une fonction dans une DLL.
* `CreateRemoteThread` → Exécuter du code dans un autre processus.

---

## **Pré-requis**

* **Windows** (testé sur Windows 10/11)
* **Rust** installé → [Installer Rust](https://www.rust-lang.org/tools/install)
* Une DLL compilée à injecter.

---

## **Utilisation**

1. Cloner le dépôt :

   ```bash
   git clone https://github.com/Psych3-N1x/dll-injection-rust.git
   cd dll-injection-rust
   ```

2. Modifier le chemin vers votre DLL dans `main.rs` :

   ```rust
   let path_to_dll = "C:\\Path\\To\\Your\\dll.dll\0";
   ```

3. Compiler le projet :

   ```bash
   cargo build --release
   ```

4. Lancer :

   ```bash
   target\release\dll-injection-rust.exe
   ```

---

## **Exemple de sortie**

```
notepad.exe is not running, launching it...
Successfully launched notepad.exe with PID: 1234
[+] Got handle to process ID 1234, handle: 0x000001
[+] Handle to kernel32.dll: 0x00007FF
[+] Address of LoadLibraryA: 0x00007FF
[+] Remote buffer base address: 0x001F0000
[+] Bytes written to remote process: 25
[+] Thread created successfully, handle: 0x000002, thread ID: 5678
[+] DLL injection initiated!
```

---

## **Avertissement**

Ce projet est **à but éducatif et de recherche uniquement**.
**N’UTILISEZ PAS** cette technique sur un système sans autorisation explicite.
L’auteur décline toute responsabilité en cas de mauvaise utilisation.

---
## **Attention**

[Voir la licence MIT](LICENSE)

-----------------------

## **Pay Attention**

[View it](LICENSE)
