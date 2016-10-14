/****************************
 * AESUtils.java
 * 
 * Contains utility functions for the main AES class
 ****************************/
 
class AESUtils {
    private static byte[] sBox  = javax.xml.bind.DatatypeConverter.parseHexBinary("637C777BF26B6FC53001672BFED7AB76CA82C97DFA5947F0ADD4A2AF9CA472C0B7FD9326363FF7CC34A5E5F171D8311504C723C31896059A071280E2EB27B27509832C1A1B6E5AA0523BD6B329E32F8453D100ED20FCB15B6ACBBE394A4C58CFD0EFAAFB434D338545F9027F503C9FA851A3408F929D38F5BCB6DA2110FFF3D2CD0C13EC5F974417C4A77E3D645D197360814FDC222A908846EEB814DE5E0BDBE0323A0A4906245CC2D3AC629195E479E7C8376D8DD54EA96C56F4EA657AAE08BA78252E1CA6B4C6E8DD741F4BBD8B8A703EB5664803F60E613557B986C11D9EE1F8981169D98E949B1E87E9CE5528DF8CA1890DBFE6426841992D0FB054BB16");
    private static byte[] rcon  = javax.xml.bind.DatatypeConverter.parseHexBinary("8D01020408102040801B366CD8AB4D9A2F5EBC63C697356AD4B37DFAEFC5913972E4D3BD61C29F254A943366CC831D3A74E8CB8D01020408102040801B366CD8AB4D9A2F5EBC63C697356AD4B37DFAEFC5913972E4D3BD61C29F254A943366CC831D3A74E8CB8D01020408102040801B366CD8AB4D9A2F5EBC63C697356AD4B37DFAEFC5913972E4D3BD61C29F254A943366CC831D3A74E8CB8D01020408102040801B366CD8AB4D9A2F5EBC63C697356AD4B37DFAEFC5913972E4D3BD61C29F254A943366CC831D3A74E8CB8D01020408102040801B366CD8AB4D9A2F5EBC63C697356AD4B37DFAEFC5913972E4D3BD61C29F254A943366CC831D3A74E8CB8D");
    private static byte[] iSBox = javax.xml.bind.DatatypeConverter.parseHexBinary("52096AD53036A538BF40A39E81F3D7FB7CE339829B2FFF87348E4344C4DEE9CB547B9432A6C2233DEE4C950B42FAC34E082EA16628D924B2765BA2496D8BD12572F8F66486689816D4A45CCC5D65B6926C704850FDEDB9DA5E154657A78D9D8490D8AB008CBCD30AF7E45805B8B34506D02C1E8FCA3F0F02C1AFBD0301138A6B3A9111414F67DCEA97F2CFCEF0B4E67396AC7422E7AD3585E2F937E81C75DF6E47F11A711D29C5896FB7620EAA18BE1BFC563E4BC6D279209ADBC0FE78CD5AF41FDDA8338807C731B11210592780EC5F60517FA919B54A0D2DE57A9F93C99CEFA0E03B4DAE2AF5B0C8EBBB3C83539961172B047EBA77D626E169146355210C7D");
    private static byte[] gm_2  = javax.xml.bind.DatatypeConverter.parseHexBinary("00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e80828486888a8c8e90929496989a9c9ea0a2a4a6a8aaacaeb0b2b4b6b8babcbec0c2c4c6c8caccced0d2d4d6d8dadcdee0e2e4e6e8eaeceef0f2f4f6f8fafcfe1b191f1d131117150b090f0d030107053b393f3d333137352b292f2d232127255b595f5d535157554b494f4d434147457b797f7d737177756b696f6d636167659b999f9d939197958b898f8d83818785bbb9bfbdb3b1b7b5aba9afada3a1a7a5dbd9dfddd3d1d7d5cbc9cfcdc3c1c7c5fbf9fffdf3f1f7f5ebe9efede3e1e7e5");
    private static byte[] gm_3  = javax.xml.bind.DatatypeConverter.parseHexBinary("000306050c0f0a09181b1e1d14171211303336353c3f3a39282b2e2d24272221606366656c6f6a69787b7e7d74777271505356555c5f5a59484b4e4d44474241c0c3c6c5cccfcac9d8dbdeddd4d7d2d1f0f3f6f5fcfffaf9e8ebeeede4e7e2e1a0a3a6a5acafaaa9b8bbbebdb4b7b2b1909396959c9f9a99888b8e8d848782819b989d9e97949192838085868f8c898aaba8adaea7a4a1a2b3b0b5b6bfbcb9bafbf8fdfef7f4f1f2e3e0e5e6efece9eacbc8cdcec7c4c1c2d3d0d5d6dfdcd9da5b585d5e57545152434045464f4c494a6b686d6e67646162737075767f7c797a3b383d3e37343132232025262f2c292a0b080d0e07040102131015161f1c191a");
    private static byte[] gm_9  = javax.xml.bind.DatatypeConverter.parseHexBinary("0009121b242d363f48415a536c657e779099828bb4bda6afd8d1cac3fcf5eee73b3229201f160d04737a6168575e454caba2b9b08f869d94e3eaf1f8c7ced5dc767f646d525b40493e372c251a130801e6eff4fdc2cbd0d9aea7bcb58a8398914d445f5669607b72050c171e2128333addd4cfc6f9f0ebe2959c878eb1b8a3aaece5fef7c8c1dad3a4adb6bf8089929b7c756e6758514a43343d262f1019020bd7dec5ccf3fae1e89f968d84bbb2a9a0474e555c636a71780f061d142b2239309a938881beb7aca5d2dbc0c9f6ffe4ed0a0318112e273c35424b5059666f747da1a8b3ba858c979ee9e0fbf2cdc4dfd63138232a151c070e79706b625d544f46");
    private static byte[] gm_11 = javax.xml.bind.DatatypeConverter.parseHexBinary("000b161d2c273a3158534e45747f6269b0bba6ad9c978a81e8e3fef5c4cfd2d97b706d66575c414a2328353e0f041912cbc0ddd6e7ecf1fa9398858ebfb4a9a2f6fde0ebdad1ccc7aea5b8b38289949f464d505b6a617c771e1508033239242f8d869b90a1aab7bcd5dec3c8f9f2efe43d362b20111a070c656e737849425f54f7fce1eadbd0cdc6afa4b9b28388959e474c515a6b607d761f1409023338252e8c879a91a0abb6bdd4dfc2c9f8f3eee53c372a21101b060d646f727948435e55010a171c2d263b3059524f44757e6368b1baa7ac9d968b80e9e2fff4c5ced3d87a716c67565d404b2229343f0e051813cac1dcd7e6edf0fb9299848fbeb5a8a3");
    private static byte[] gm_13 = javax.xml.bind.DatatypeConverter.parseHexBinary("000d1a1734392e236865727f5c51464bd0ddcac7e4e9fef3b8b5a2af8c81969bbbb6a1ac8f829598d3dec9c4e7eafdf06b66717c5f524548030e1914373a2d206d60777a5954434e05081f12313c2b26bdb0a7aa8984939ed5d8cfc2e1ecfbf6d6dbccc1e2eff8f5beb3a4a98a87909d060b1c11323f28256e6374795a57404ddad7c0cdeee3f4f9b2bfa8a5868b9c910a07101d3e332429626f7875565b4c41616c7b7655584f420904131e3d30272ab1bcaba685889f92d9d4c3ceede0f7fab7baada0838e9994dfd2c5c8ebe6f1fc676a7d70535e49440f0215183b36212c0c01161b3835222f64697e73505d4a47dcd1c6cbe8e5f2ffb4b9aea3808d9a97");
    private static byte[] gm_14 = javax.xml.bind.DatatypeConverter.parseHexBinary("000e1c123836242a707e6c624846545ae0eefcf2d8d6c4ca909e8c82a8a6b4badbd5c7c9e3edfff1aba5b7b9939d8f813b352729030d1f114b455759737d6f61ada3b1bf959b8987ddd3c1cfe5ebf9f74d43515f757b69673d33212f050b191776786a644e40525c06081a143e30222c96988a84aea0b2bce6e8faf4ded0c2cc414f5d537977656b313f2d230907151ba1afbdb39997858bd1dfcdc3e9e7f5fb9a948688a2acbeb0eae4f6f8d2dccec07a746668424c5e500a041618323c2e20ece2f0fed4dac8c69c92808ea4aab8b60c02101e343a28267c72606e444a585637392b250f01131d47495b557f71636dd7d9cbc5efe1f3fda7a9bbb59f91838d");
    private static byte[] galois_matrix     = javax.xml.bind.DatatypeConverter.parseHexBinary("02030101010203010101020303010102");
    private static byte[] galois_matrix_inv = javax.xml.bind.DatatypeConverter.parseHexBinary("0e0b0d09090e0b0d0d090e0b0b0d090e");
    /**************************************************************************/
    
    
    /***** keyExpansionCore
     * Applies substitution-box for further obscuration
     */
    private static void keyExpansionCore(byte[] prevKey, int i) {
        int ndx;
        
        // rotate
        byte temp = prevKey[0];
        for(ndx = 0; ndx < 3; ndx ++) {
            prevKey[ndx] = prevKey[ndx + 1];
        }
        prevKey[3] = temp;

        // apply s-box
        for(int j = 0; j < 4; j++) {
            prevKey[j] = AESUtils.sBox[prevKey[j] + 128];
        }

        // xor first byte with rcon
        prevKey[0] ^= AESUtils.rcon[i];
    }
    /**************************************************************************/
    

    /***** expandKey
     * reference: https://en.wikipedia.org/wiki/Rijndael_key_schedule
     */
    protected static void expandKey(byte[] fullKey) {
        int ndx = 32; // tracks where in the expanded key array we are.
        byte[] temp = new byte[4];
    
        int i;
        for(i = 1; i < 7; i++) {
            System.arraycopy(fullKey, ndx - 4, temp, 0, 4);
            keyExpansionCore(temp, i);
            System.arraycopy(temp, 0, fullKey, ndx, 4);
            
            ndx = xor32Before(fullKey, ndx);
            ndx = generate12Bytes(fullKey, ndx);
            
            System.arraycopy(fullKey, ndx - 4, fullKey, ndx, 4);
            for(int j = 0; j < 4; j++) {
                fullKey[ndx + j] = AESUtils.sBox[(fullKey[ndx + j] + 256) % 256];
                fullKey[ndx + j] ^= fullKey[ndx - 32 + j];
            }
            ndx += 4;
            
            ndx = generate12Bytes(fullKey, ndx);
        }
        
        System.arraycopy(fullKey, ndx - 4, temp, 0, 4);
        keyExpansionCore(temp, i);
        System.arraycopy(temp, 0, fullKey, ndx, 4);
        
        ndx = xor32Before(fullKey, ndx);
        ndx = generate12Bytes(fullKey, ndx);
    }
    /**************************************************************************/
    
    
    /***** generate12Bytes
     *
     * generate the next 12 bytes of key.
     * returns current index.
     */
    private static int generate12Bytes(byte[] fullKey, int ndx) {
        for(int i = 0; i < 3; i++) {
            System.arraycopy(fullKey, ndx - 4, fullKey, ndx, 4);
            ndx = xor32Before(fullKey, ndx);
        }
        return ndx;
    }
    /**************************************************************************/
    
    
    /***** xor32Before
     * exclusive or 4 current bytes with the 4 bytes 32 previous. 
     * returns current index.
     */
    private static int xor32Before(byte[] fullKey, int ndx) {
        for(int i = 0; i < 4; i++) {
            fullKey[ndx + i] ^= fullKey[ndx - 32 + i];   
        }
        return ndx + 4;
    }
    /**************************************************************************/
    
    
    /***** addRoundKey
     * combine the state with a part of the expanded key that corresponds with 
     * the current round number
     */
    protected static void addRoundKey(byte[] input, byte[] fullKey, int roundNum) {
        // input length is checked to be 16
        for(int i = 0; i < input.length; i++) {
            input[i] ^= fullKey[roundNum * input.length + i];
        }
    }
    /**************************************************************************/
    
    
    /***** subBytes
     * perform substitution for obscuration with sub-box
     */
    protected static void subBytes(byte[] input) {
        // input length is checked to be 16
        for(int i = 0; i < input.length; i++) {
            input[i] = AESUtils.sBox[(input[i] + 256) % 256];
        }
    }
    /**************************************************************************/
    
    
    /***** iSubBytes
     * perform substitution for obscuration with i-sub-box
     */
    protected static void iSubBytes(byte[] input) {
        // input length is checked to be 16
        for(int i = 0; i < input.length; i++) {
            input[i] = AESUtils.iSBox[(input[i] + 256) % 256];
        }
    }
    /**************************************************************************/
    
    
    /***** shiftRows
     * Same as iShiftRows but performs opposite rotation (left)
     * 
     * Function performs the following order of operations:
     * input byte array > 4x4 matrix > rotate matrix > byte array
     * 
     * shiftRows input is of form:
     * [b0 b1 b2 b3 b4 b5 b6 b8 b9 b10 b11 b12 b13 b14 b15]
     * 
     * rotate input should have form:
     * [b0 b4 b8 b12
     *  b1 b5 b9 b13
     *  b2 b6 b10 b14
     *  b3 b7 b11 b15]
     * 
     */
    protected static void shiftRows(byte[] input) {
        byte temp;
        byte[][] shifted = new byte[4][4];
        
        //creates matrix
        AESUtils.oneDtwoD(input, shifted);
        
        //rotate matrix
        for(int i = 0; i < 4; i++) {
            AESUtils.rotateLeft(shifted[i], i);
        }
        
        //recreate byte array
        AESUtils.twoDoneD(shifted, input);
    }
    /**************************************************************************/
    
    
    /***** iShiftRows
     * Same as shiftRows but performs opposite rotation (pesudo-right)
     * 
     * Function performs the following order of operations:
     * input byte array > 4x4 matrix > rotate matrix > byte array
     * 
     * shiftRows input is of form:
     * [b0 b1 b2 b3 b4 b5 b6 b8 b9 b10 b11 b12 b13 b14 b15]
     * 
     * rotate input should have form:
     * [b0 b4 b8 b12
     *  b1 b5 b9 b13
     *  b2 b6 b10 b14
     *  b3 b7 b11 b15]
     * 
     */
    protected static void iShiftRows(byte[] input) {
        byte temp;
        byte[][] shifted = new byte[4][4];
        
        //creates 4x4 matrix
        AESUtils.oneDtwoD(input, shifted);
        
        
        for(int i = 0; i < 4; i++) {
            AESUtils.rotateLeft(shifted[i], 4 - i);
        }
        
        //recreate byte array
        AESUtils.twoDoneD(shifted, input);
    }
    /**************************************************************************/
    
    
    /******** oneDtwoD and twoDoneD pair ********/
    /***** oneDtwoD
     * Takes input byte array and transforms into 4x4 matrix
     * Note: gets the input into the same format as wikipedia.
     */
    private static void oneDtwoD(byte[] source, byte[][] dest) {
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                dest[i][j] = source[4 * j + i];
            }
        }    
    }
    /***** twoDoneD
     * Takes input 4x4 matrix and outputs to length 16 byte array
     */
    private static void twoDoneD(byte[][] source, byte[] dest) {
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                dest[4 * j + i] = source[i][j];
            }
        }
    }
    /**************************************************************************/
    
    
    /***** rotateLeft
     * Takes input byte array and moves all items to the left <<<<
     * Any flowover on left side gets put at the end on the right.
     */
    private static void rotateLeft(byte[] input, int times) {
        if (times % 4 == 0) {
            return;
        }
        
        for(int i = 0; i < times; i++) {
            byte temp = input[0];
            for(int j = 0; j < input.length - 1; j++) {
                input[j] = input[j + 1];
            }
            input[input.length - 1] = temp;
        }
    }
    /**************************************************************************/
    
    
    /***** mixColumns
     * For mixColumns, we are trying to achieve matrix
     * column multiplication in the finite field.  We will
     * forgo actually implementing multiplication in the
     * field, and instead use lookup tables.  Addition is
     * simply XOR.  What we want is:
     *  _  _     _       _  _  _
     * | m0 |   | 2 3 1 1 || b0 |
     * | m1 | = | 1 2 3 1 || b1 | 
     * | m2 |   | 1 1 2 3 || b2 |
     * | m3 |   | 3 1 1 2 || b3 |
     *  ‾  ‾     ‾       ‾  ‾  ‾ 
     * for each column b0-3, b4-7, etc.  For the example
     * above:
     *
     *  m0 = gm_2[b0] ^ gm_3[b1] ^ b2 ^ b3
     *  m1 = b0 ^ gm_2[b1] ^ gm_3[b2] ^ b3
     *  
     *  ...and so on.
     *
     *  The inverse case is different, in that we are tring
     *  instead to achieve the following:
     *  _  _     _           _  _  _
     * | b0 |   | 14 11 13  9 || m0 |
     * | b1 | = |  9 14 11 13 || m1 | 
     * | b2 |   | 13  9 14 11 || m2 |
     * | b3 |   | 11 13  9 14 || m3 |
     *  ‾  ‾     ‾           ‾  ‾  ‾ 
     * To invoke mixColumns for the inverse case, the
     * boolean inv must be set to true:
     *
     * mixColumns(data, true);  // Inverse mixColumns
     *
     * Otherwise the boolean should be set to false:
     *
     * mixColumns(data, false); // Regular mixColumns
     */
    protected static void mixColumns(byte[] input, boolean inv) {
        byte[] mixed = new byte[16];
        byte[] matrix;
        
        if (inv) {
            matrix = galois_matrix_inv;
        } else {
            matrix = galois_matrix;
        }
        // column-matrix multiplication
        for (int i = 0; i < 16; i++)
        {
            byte sum = 0x0;
            for (int j = (i % 4) * 4, k = 0; j < ((i % 4) * 4) + 4; j++, k++)
            {
                switch (matrix[j]) {
                    case 1: sum ^= (input[((i / 4) * 4) + k] & 0xFF);
                        break;
                    case 2: sum ^= gm_2[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                    case 3: sum ^= gm_3[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                    case 9: sum ^= gm_9[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                    case 11: sum ^= gm_11[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                    case 13: sum ^= gm_13[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                    case 14: sum ^= gm_14[input[((i / 4) * 4) + k] & 0xFF];
                        break;
                }
            }
            mixed[i] = sum;
        }
    }
}