# WRITE UP ()

Bon, on ouvre la VM, on regarde le dossier où se trouve le flag. Dans un premier temps on voit que seul ce dossier est lock, ça veut dire que l’exe s’exécute par défaut soit dans un dossier en particulier soit dans le dossier où il se trouve. 

Donc je le place dans un dossier avec un fichier texte, je l’exécute pour vérifier, et magie il ne chiffre que le dossier où il se trouve… 

Mais surtout au moment de sa réutilisation dans le même dossier, il m’affiche “enter a key”… 

Si il demande une clé ça sous entend qu’il en a besoin pour déchiffrer, pour une meilleure compréhension je le désassemble : 

Pour ce faire j’utilise IDA(free) pour obtenir le graphique : 

![Untitled](WRITE%20UP%20()%20eda56aa1d7f54fe29284a62abe232c02/Untitled.png)

Petit zoom sur la fonction main : 

```nasm
; Attributes: bp-based frame fpd=2E0h

; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

phkResult= qword ptr -340h
lpcbData= qword ptr -338h
var_330= byte ptr -330h
Str2= byte ptr -230h
cbData= dword ptr -124h
Data= byte ptr -120h
Type= dword ptr -14h
hKey= qword ptr -10h
var_4= dword ptr -4
arg_0= dword ptr  10h
arg_8= qword ptr  18h

push    rbp
sub     rsp, 360h
lea     rbp, [rsp+80h]
mov     [rbp+2E0h+arg_0], ecx
mov     [rbp+2E0h+arg_8], rdx
call    __main
lea     rcx, stda       ; char *
call    _Z2opPc         ; op(char *)
lea     rax, [rbp+2E0h+hKey]
mov     [rsp+360h+phkResult], rax ; phkResult
mov     r9d, 20019h     ; samDesired
mov     r8d, 0          ; ulOptions
lea     rdx, stda       ; lpSubKey
mov     rcx, 0FFFFFFFF80000001h ; hKey
mov     rax, cs:__imp_RegOpenKeyExA 
call    rax ; __imp_RegOpenKeyExA
mov     [rbp+2E0h+var_4], eax
cmp     [rbp+2E0h+var_4], 0
jz      short loc_401C7B
```

On y trouve quelque informations : 

```nasm
mov     rax, cs:__imp_RegOpenKeyExA 
call    rax ; __imp_RegOpenKeyExA
```

La clé est stockée dans le registre Windows (pas à ce stade mais on a l’information, donc si elle est stocké il va surement vérifié et comparer à celle qu’on lui donne)

Donc on descend le graphique (le coté sans argument pour ma part) 

Jusqu’à ce bloc qui m’intéresse : 

```nasm
lea     rax, [rbp+2E0h+Str2]
mov     rdx, rax
lea     rcx, aCurrentWorking ; "Current working dir: %s\n"
call    printf
lea     rcx, aEnterKey  ; "Enter key: "
call    printf
lea     rax, [rbp+2E0h+var_330]
mov     rdx, rax
lea     rcx, a255s      ; "%255s"
call    scanf
lea     rdx, [rbp+2E0h+var_330] ; Str2
lea     rax, [rbp+2E0h+Data]
mov     rcx, rax        ; Str1
call    strcmp
test    eax, eax
jnz     short loc_401FB0
```

Ce sont les deux dernières instructions qui nous intéressent 

```nasm
test eax, eax  comparaison des valeurs -> pas très intéressant à modifier 
jnz short loc401FB0 alors que le saut qui suit le test en fonction du résultat l'ai 
```

Donc on va échanger le jnz par un jz car si la bonne clé est donnée le test va renvoyer 0 donc l’instruction nous fera jump au bloc qui contient WrongKey : 

```nasm
loc_401FB0:
lea     rcx, aWrongKey  ; "Wrong key"
call    puts
mov     eax, 1
jmp     short loc_401FFB
```

Donc on doit juste changer une instruction, fait avec GHIDRA pour ma part : 

![Untitled](WRITE%20UP%20()%20eda56aa1d7f54fe29284a62abe232c02/Untitled%201.png)

On recherche le block.. 

![Untitled](WRITE%20UP%20()%20eda56aa1d7f54fe29284a62abe232c02/Untitled%202.png)

ctrl shift g 

![Untitled](WRITE%20UP%20()%20eda56aa1d7f54fe29284a62abe232c02/Untitled%203.png)

On switch 75 15 à 74 15 et : 

![Untitled](WRITE%20UP%20()%20eda56aa1d7f54fe29284a62abe232c02/Untitled%204.png)

On obtient notre petit patch :