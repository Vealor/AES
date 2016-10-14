/******************************************************************************
 * SENG 360  -  Assignment 2
 * 
 * Konrad Schultz  
 * Jim Galloway 
 * Jakob Roberts
 * 
 ******************************************************************************/
/*############################################################################*/
/****************************
 * AES.java
 * 
 * Contains the Main function and the two main classes Encrypter and Decrypter
 ****************************/

import java.io.*;
import java.util.*;

/****************************
 * Encrypter
 * 
 * Main Encryption function called from AES Main
 * reference for algorithm: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 ****************************/
class Encrypter {
    private byte[] key;
    private BufferedReader inFile;
    private FileOutputStream outFile;

    public Encrypter(byte[] key, String inFileName) throws FileNotFoundException {
        this.key = key;
        this.inFile = new BufferedReader(new FileReader(inFileName));
        this.outFile = new FileOutputStream(inFileName + ".enc");
    }

    public void encrypt() throws IOException {
        byte[] expandedKey = new byte[240];
        System.arraycopy(this.key, 0, expandedKey, 0, this.key.length);
        AESUtils.expandKey(expandedKey);
        
        byte[] buffer;
        for(String line = this.inFile.readLine(); line != null; line = this.inFile.readLine()) {
            buffer = javax.xml.bind.DatatypeConverter.parseHexBinary(line);
            if(buffer.length != 16) {
                System.out.println("Input line is not 128 bits");
                System.exit(1);
            }
            
            /* Contains
             *  1. subBytes
             *  2. shiftRows
             *  3. mixColumns
             *  4. addRoundkey
             */
            
            // Initial Round
            AESUtils.addRoundKey(buffer, expandedKey, 0);
            
            // 13 middle repeated rounds
            for(int i = 0; i < 14; i++){
                AESUtils.subBytes(buffer); // Part 1
                AESUtils.shiftRows(buffer); // Part 2
                AESUtils.mixColumns(buffer, false); // Part 3
                AESUtils.addRoundKey(buffer, expandedKey, i); // Part 4
            }
            
            // Final Round without mixColumns
            AESUtils.subBytes(buffer);
            AESUtils.shiftRows(buffer);
            AESUtils.addRoundKey(buffer, expandedKey, 14);
            
            String output = javax.xml.bind.DatatypeConverter.printHexBinary(buffer);
            output += "\n";
            this.outFile.write(output.getBytes());
        }
    }
}

/****************************
 * Decrypter
 * 
 * Main Decryption function called from AES Main
 ****************************/
class Decrypter {
    private byte[] key;
    private BufferedReader inFile;
    private FileOutputStream outFile;
    
    public Decrypter(byte[] key, String inFileName) throws FileNotFoundException {
        this.key = key;
        this.inFile = new BufferedReader(new FileReader(inFileName));
        this.outFile = new FileOutputStream(inFileName + ".dec");
    }
    
    public void decrypt() throws IOException {
        byte[] expandedKey = new byte[240];
        System.arraycopy(this.key, 0, expandedKey, 0, this.key.length);
        AESUtils.expandKey(expandedKey);
        
        byte[] buffer;
        for(String line = this.inFile.readLine(); line != null; line = this.inFile.readLine()) {
            buffer = javax.xml.bind.DatatypeConverter.parseHexBinary(line);
            if(buffer.length != 16) {
                System.out.println("Input line is not 128 bits");
                System.exit(1);
            }
            
            // initial round
            AESUtils.addRoundKey(buffer, expandedKey, 14);
            AESUtils.iShiftRows(buffer);
            AESUtils.iSubBytes(buffer);
            
            // 14 middle repeated rounds
            for(int i = 13; i >= 0; i--){
                AESUtils.addRoundKey(buffer, expandedKey, i);
                AESUtils.mixColumns(buffer, true);
                AESUtils.iShiftRows(buffer);
                AESUtils.iSubBytes(buffer);
            }
            
            // final round
            AESUtils.addRoundKey(buffer, expandedKey, 0);
            
            String output = javax.xml.bind.DatatypeConverter.printHexBinary(buffer);
            output += "\n";
            this.outFile.write(output.getBytes());
        }
    }
}


/****************************
 * AES
 * 
 * Main function of the program
 * Contains input parsing from command line, file IO, and exceptions
 ****************************/
class AES {
    public static void main(String[] args) {
        if(args.length != 3) {
            System.out.println("USAGE:\tjava AES option keyFile inputFile");
            System.exit(0);
        }

        String option = args[0];
        String keyFileName = args[1];
        String inFileName = args[2];

        byte[] key = { 0 };

        // Pull in file
        try {
            BufferedReader keyReader = new BufferedReader(new FileReader(keyFileName));
            String keyString = keyReader.readLine();
            key = javax.xml.bind.DatatypeConverter.parseHexBinary(keyString);
            
            if(key.length != 32) {
                System.out.println("Key not 256 bits");
                System.exit(1);
            }
        } catch(FileNotFoundException e) {
            System.out.println("Unable to open file");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error reading file");
            System.exit(1);
        }

        // user input: encrypt or decrypt
        if(option.equals("e")) {
            try {
                // attempt encryption
                Encrypter enc = new Encrypter(key, inFileName);
                enc.encrypt();
            } catch(FileNotFoundException e) {
                System.out.println("Unable to open file");
                System.exit(1);
            } catch(IOException e) {
                System.out.println("Error reading file");
                System.exit(1);
            }
        } else if(option.equals("d")) {
            try {
                // attempt decryption
                Decrypter dec = new Decrypter(key, inFileName);
                dec.decrypt();
            } catch(FileNotFoundException e) {
                System.out.println("Unable to open file");
                System.exit(1);
            } catch(IOException e) {
                System.out.println("Error reading file");
                System.exit(1);
            }
        } else {
            System.out.println("option flag should be d|e");
            System.exit(0);
        }
    }
}