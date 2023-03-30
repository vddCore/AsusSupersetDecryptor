# ASUS Superset ZIP decryptor
You might think I have a personal vendetta against ASUS.  
...maybe I do. So what.

## Scheme details
To package the data in the way ASUS do:

0. Split a regular ZIP file into two at the point where ZIP central directory ends.
1. Calculate a 32-bit checksum for that data (no clue what that checksum might be, maybe CRC32), add it as little-endian bytes to the end of central directory section.
2. Encrypt the central directory section using whatever RSA public key ASUS use. I don't give a shit what it might be.
3. Write the encrypted section down to disk with `.enc` extension.
4. Write the remainder of the data to disk with `.dat` extension.
5. Package both files into another ZIP (smart af).

To reconstruct the ZIP into a proper, browsable one look into `SupersetZip.cs` file in this repository. 

What in the ever-loving-fuck is the purpose of that scheme probably only people at ASUS' S/W department know.  
What I know is I wouldn't want to touch that department with a 10-yard stick.
