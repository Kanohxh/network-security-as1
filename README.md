# network-security-as1

## Assignment 1

- [File introduction](#chapter1)
  - [Alice](#section1-1)
    - [src](#section1-1-1)
  - [Bob](#section1-2)
    - [src](#src-section1-2-1)
- [How to run](#chapter2)
  - [Preliminary work](#section2-1)
  - [Host and Client](#section2-2)
    
## File introduction {#chapter1}
### Alice {#section1-1}
contain `out` file , `Alice.iml` , `password.txt` , `pk.bin` , `sk.bin` ,`src` file

    `password.txt` 
stores user name and the hash of the corresponding password in the shape of 

    `Bob,H(password)`
#### src {#section1-1-1}
contain 
    `Host.java` , `KeyGen.java`

    Host.java

The running code for Host

    KeyGen.java

Code that generates public and private keys

### Bob {#section1-2}
contain `out` file , `Bob.iml` , `hash.txt`

    hash.txt
stores the hash of the corresponding password

#### src {#section1-2-1}
contain 
    `Client.java` , `HashGen.java`

    Client.java

The running code for Client

    HashGen.java

Calculate the hash of the public key

## How to run {#chapter2}

### Preliminary work {#section2-1}

>This program runs in `java17` environment. 

>First run to ensure that the `password.txt` file in the `Alice` directory contains the user name and the hash of the corresponding password, run `KeyGen.java` to get the public and private keys, and then run `HashGen.java` to get the hash of the public key.

>Completion of preliminary work.

### Host and Client {#section2-2}

>Run `Host.java` to prepare to receive data.

>Run the `Client.java`, the program prompts you to enter the user name, and then enter the password as prompted.
Host compares and returns whether to authorize.


