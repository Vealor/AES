// NOTE!!! TODO!! currently reads in 32 bytes but each digit is a hex digit so 
// it should be 16 bytes per 32 hex digits. Same with input file.
// Try reading file by line and then use the hexString -> bytes function

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.util.Arrays;

class Encrypter {
    private static byte[] sBox = javax.xml.bind.DatatypeConverter.parseHexBinary("637C777BF26B6FC53001672BFED7AB76CA82C97DFA5947F0ADD4A2AF9CA472C0B7FD9326363FF7CC34A5E5F171D8311504C723C31896059A071280E2EB27B27509832C1A1B6E5AA0523BD6B329E32F8453D100ED20FCB15B6ACBBE394A4C58CFD0EFAAFB434D338545F9027F503C9FA851A3408F929D38F5BCB6DA2110FFF3D2CD0C13EC5F974417C4A77E3D645D197360814FDC222A908846EEB814DE5E0BDBE0323A0A4906245CC2D3AC629195E479E7C8376D8DD54EA96C56F4EA657AAE08BA78252E1CA6B4C6E8DD741F4BBD8B8A703EB5664803F60E613557B986C11D9EE1F8981169D98E949B1E87E9CE5528DF8CA1890DBFE6426841992D0FB054BB16");
    private byte[] key;
    private FileInputStream inFile;
    private FileOutputStream outFile;


    public Encrypter(byte[] key, String inFileName) throws FileNotFoundException {
        this.key = key;
        this.inFile = new FileInputStream(inFileName);
        this.outFile = new FileOutputStream(inFileName + ".enc");
        System.out.println(Arrays.toString(sBox));
    }

    public void encrypt() throws IOException {
        byte[] buffer = new byte[32];
        while(this.inFile.read(buffer) == 32) {
            this.outFile.write(buffer);
            this.inFile.read(); //read newline
        }
    }
}

class AES {
    public static void main(String[] args) {
        if(args.length != 3) {
            System.out.println("USAGE:\tjava AES option keyFile inputFile");
            System.exit(0);
        }

        String option = args[0];
        String keyFileName = args[1];
        String inFileName = args[2];

        byte[] key = new byte[64];

        try {
            FileInputStream keyStream = new FileInputStream(keyFileName);
            if(keyStream.read(key) != 64) {
                System.out.println("Error reading key, not 256 bits");
                System.exit(1);
            }
            keyStream.close();            
        } catch(FileNotFoundException e) {
            System.out.println("Unable to open file");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error reading file");
            System.exit(1);
        }

        if(option.equals("e")) {
            try {
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

        }
    }
}