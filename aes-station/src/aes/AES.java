package aes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Emiljan Dusha
 */
public abstract class AES {
   
    
    private final int NUM_ROUNDS = 0;
    private final int KEY_BLOCK = 0;
    public final int MESSAGE_BLOCK = 16;
    
    protected Integer[] sBox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    
    protected int[] matrix = {
        2, 3, 1, 1,
        1, 2, 3, 1, 
        1, 1, 2, 3,
        3, 1, 1, 2
    };

    protected int[] invMatrix = {
        14, 11, 13, 9,
        9, 14, 11, 13,
        13, 9, 14, 11,
        11, 13, 9, 14
    };

    protected String[] rcon = {
        "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"
    };
    
    protected int[] SubBytes(int[] message){
        int[] subbed = new int[message.length];

        for (int i=0; i<subbed.length; i++)
            subbed[i] = sBox[(message[i]/MESSAGE_BLOCK) * MESSAGE_BLOCK + (message[i]%MESSAGE_BLOCK)];
        
        return subbed;
    }
    
    protected int[] invSubBytes(int[] cipher){
        int[] message = new int[cipher.length];
        List<Integer> subList = Arrays.asList(sBox);
        
        for (int i=0; i<message.length; i++)
            message[i] = subList.indexOf(cipher[i]);
        
        return message;
    }
    
    protected int[] ShiftRows(int[] message){
//        i represents rows
        for (int i=1; i<4; i++)
//            k represents number of cells to be shifted in each row
            for (int k=0; k<i; k++)
//                j represents each individual shift to complete a round
                for (int j=0; j<3; j++){
                    int temp = message[i+4*j];
                    message[i+4*j] = message[i+4*(j+1)];
                    message[i+4*(j+1)] = temp;
                }
        return message;
    }
    
    protected int[] invShiftRows(int[] cipher){
//        i represents rows
        for (int i=3; i>0; i--)
//            k represents number of cells to be shifted in each row
            for (int k=i; k>0; k--)
//                j represents each individual shift to complete a round
                for (int j=3; j>0; j--){
                    int temp = cipher[j*4+i];
                    cipher[j*4+i] = cipher[(j-1)*4+i];
                    cipher[(j-1)*4+i] = temp;
                }
        
        return cipher;
    }
        
    protected int[] MixColumns(int[] message){
        
        int[] mixed = new int[message.length];
        int index = 0;
        int cell, current;
//        i represents columns
        for (int i=0; i<4; i++)
//            j iterates each value of the column
            for (int j=0; j<4; j++){
                cell = 0;
//                k represents the addition of the 4 values as one cell
                for (int k=0; k<4; k++){
                    current = galoisMultiply(message[i*4+k], matrix[k+j*4]);
                    cell ^= current;
                }
                mixed[index++] = cell;
            }
        return mixed;
    }
    
    protected int[] invMixColumns(int[] cipher){
        int[] message = new int[cipher.length];
        int index = 0;
        int cell, current;
        for (int i=0; i<4; i++){
            for (int j=0; j<4; j++){
                cell = 0;
                for (int k=0; k<4; k++){
                    current = galoisMultiply(cipher[i*4+k], invMatrix[k+j*4]);
                    cell ^= current;
                }
                message[index++] = cell;
            }
        }
        
        return message;
    }
    
    public int[] KeySchedule(int[] masterKey){
        int[] keyArray = new int[MESSAGE_BLOCK*NUM_ROUNDS];
        int[] paddedKey = new int[masterKey.length];
        int c = KEY_BLOCK;
        int rconIndex = 0;
        
        
        
        System.arraycopy(masterKey, 0, keyArray, 0, masterKey.length);
        int[] wordSegment = new int[4];
                
        while (c < MESSAGE_BLOCK*NUM_ROUNDS){
            for (int i=0; i<4; i++)
                wordSegment[i] = keyArray[c+i-4];
           

            if (c%KEY_BLOCK==0){
                for (int i=0; i<3; i++){
                    int temp = wordSegment[i];
                    wordSegment[i] = wordSegment[i+1];
                    wordSegment[i+1] = temp;
                }
                wordSegment = SubBytes(wordSegment);

                wordSegment[0] ^= hex2Int(rcon[rconIndex]);
                rconIndex++;
            }

            for (int i=0; i<4; i++){
                keyArray[c] = keyArray[c-KEY_BLOCK] ^ wordSegment[i];
                c++;
            }            
        }
        return keyArray;
    }
    
    public static int[] xorBlock(int[] block, int[] roundKey){
        int[] xoredBlock = new int[block.length];
        for (int i=0; i<block.length; i++)
            xoredBlock[i] = block[i] ^ roundKey[i];
        return xoredBlock;
    }
    
    public static int[] convertIntegers(List<Integer> integers){
        int[] ret = new int[integers.size()];
        for (int i=0; i < ret.length; i++){
            ret[i] = integers.get(i).intValue();
        }
        return ret;
    }
    
    protected String encryptRoutine(ArrayList<Integer> message, int[] key, boolean debug){
        ArrayList<Integer> cipherText = new ArrayList<>(message.size());
        
        int[] subbed, shifted, mixed;
        int[] messageBlock = new int[16];
        int[] encryptedBlock = new int[16];
        
        if (message.size() != 16){
            while (message.size() % 16 != 0)
                message.add(0);
            
            double blocks = message.size()/(16*1.0);
            for (int block = 0; block < blocks; block++){
                messageBlock = convertIntegers(message.subList(block*16, block*16+16));
                
                if (debug){
                    System.out.println("Starting plaintext aaaa");
                    printArray(messageBlock);
                }

                encryptedBlock = xorBlock(messageBlock, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
                if (debug){
                    System.out.println("Starting key");
                    printArray(Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
                    System.out.println("After first XOR");
                    printArray(encryptedBlock);
                    System.out.println("");
                }

                for (int round=0; round<NUM_ROUNDS-1; round++){

                    subbed = SubBytes(encryptedBlock);
                    if (debug){
                        System.out.println("After Sub on round "+(round+1));
                        printArray(subbed);
                    }

                    shifted = ShiftRows(subbed);
                    if (debug){
                        System.out.println("After Shift on round "+(round+1));
                        printArray(shifted);
                    }

                    mixed = MixColumns(shifted);
                    if (debug){
                        System.out.println("After Mix on round "+(round+1));
                        printArray(mixed);
                    }

                    encryptedBlock = xorBlock(mixed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
                    if (debug){
                        System.out.println("Key for round "+(round+1));
                        printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
                        System.out.println("After XOR for round "+(round+1));
                        printArray(encryptedBlock);
                        System.out.println("\n");
                    }
                }

                subbed = SubBytes(encryptedBlock);
                if (debug){
                    System.out.println("After final Sub");
                    printArray(subbed);
                }

                shifted = ShiftRows(subbed);
                if (debug){
                    System.out.println("After final Shift");
                    printArray(shifted);
                }

                encryptedBlock = xorBlock(shifted, Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
                for (int i=0; i<encryptedBlock.length; i++)
                    cipherText.add(encryptedBlock[i]);
                if (debug){
                    System.out.println("Final key");
                    printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
                    System.out.println("Cipher Text");
                    printArray(encryptedBlock);
                }
            }
        } else {
            if (debug){
                    System.out.println("Starting plaintext");
                    printArray(messageBlock);
                }

                encryptedBlock = xorBlock(messageBlock, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
                if (debug){
                    System.out.println("Starting key");
                    printArray(Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
                    System.out.println("After first XOR");
                    printArray(encryptedBlock);
                    System.out.println("");
                }

                for (int round=0; round<NUM_ROUNDS-1; round++){

                    subbed = SubBytes(encryptedBlock);
                    if (debug){
                        System.out.println("After Sub on round "+(round+1));
                        printArray(subbed);
                    }

                    shifted = ShiftRows(subbed);
                    if (debug){
                        System.out.println("After Shift on round "+(round+1));
                        printArray(shifted);
                    }

                    mixed = MixColumns(shifted);
                    if (debug){
                        System.out.println("After Mix on round "+(round+1));
                        printArray(mixed);
                    }

                    encryptedBlock = xorBlock(mixed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
                    if (debug){
                        System.out.println("Key for round "+(round+1));
                        printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
                        System.out.println("After XOR for round "+(round+1));
                        printArray(encryptedBlock);
                        System.out.println("\n");
                    }
                }

                subbed = SubBytes(encryptedBlock);
                if (debug){
                    System.out.println("After final Sub");
                    printArray(subbed);
                }

                shifted = ShiftRows(subbed);
                if (debug){
                    System.out.println("After final Shift");
                    printArray(shifted);
                }

                encryptedBlock = xorBlock(shifted, Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
                for (int i=0; i<encryptedBlock.length; i++)
                    cipherText.add(encryptedBlock[i]);
                if (debug){
                    System.out.println("Final key");
                    printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
                    System.out.println("Cipher Text");
                    printArray(encryptedBlock);
                }
        }
        
        if (debug){
           System.out.println("Final Cipher text");
           System.out.println(arrayList2String(cipherText));
       }
        
        return arrayList2String(cipherText);
    }    
    
    protected String decryptRoutine(int[] cipher, int[] key, boolean debug){
        int[] decrypted = new int[cipher.length];
        int[] subbed, shifted, mixed;
        
        decrypted = xorBlock(cipher, Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
        printArray(decrypted);
        
        shifted = invShiftRows(decrypted);
        printArray(shifted);
        
        subbed = invSubBytes(shifted);
        printArray(subbed);

        System.out.println("key to be xored with:\n");

        for (int round=NUM_ROUNDS-1; round>0; round--){
            System.out.println("Now on round "+round);
            System.out.println("");
            
            decrypted = xorBlock(subbed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
            System.out.println("Round key: ");
            printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
            System.out.println("After xor: ");
            printArray(decrypted);
            
            System.out.println("Before unmix");
            printArray(decrypted);
            mixed = invMixColumns(decrypted);
            System.out.println("After unmix");
            printArray(mixed);
            
            shifted = invShiftRows(mixed);
            System.out.println("after unshift");
            printArray(shifted);
            
            subbed = invSubBytes(shifted);
            System.out.println("after unsub");
            printArray(subbed);
        }
        
        decrypted = xorBlock(subbed, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
        
        printArray(subbed);
        
        if (debug){
            System.out.println("Final key");
            printArray(Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
        }
        
        if (debug){
            System.out.println("Final Plain text");
            System.out.println(array2String(decrypted));
        }
        
        return array2String(decrypted);
    }
    
    public static int galoisAdd(int number, int addition){
        return number ^ addition;
    }
    
    public static int galoisMultiply(int number, int multiplier){
        int result = 0;

        if (multiplier == 1)
            result = number;
        
        else if (multiplier == 2){
            if (number >= 128){
                result = (number << 1) ^ 27;
            }
            else 
                result = number << 1;
        }
        else if (multiplier % 2 == 1)
            result = galoisAdd(galoisMultiply(number, multiplier-1), number);
        
        else if (multiplier % 2 == 0)
            result = galoisMultiply(galoisMultiply(number, multiplier/2), 2);
        
        
        return result % 256;
    }
     
    public static void printArray(int[] array){
        for (int i=0; i<array.length; i++)
            System.out.print(zeroPad(int2Hex(array[i]))+" ");
        System.out.println("");
    }
    
    public static void printArray(ArrayList<Integer> array){
        for (int i=0; i<array.size(); i++)
            System.out.print(zeroPad(int2Hex(array.get(i)))+" ");
        System.out.println("");
    }
    
    public static int hex2Int(String hex){
        return (int) Long.parseLong(hex, 16);
    }
    
    public static int[] string2int(String hex){
        int index = 0;
        int[] hexArray = new int[hex.length()/2];
        for (int i=0; i<hex.length(); i+=2){
            hexArray[index++] = hex2Int(new StringBuilder().append(hex.charAt(i)).append(hex.charAt(i+1)).toString());
        }
        printArray(hexArray);        
        
        return hexArray;
    }
    
    public static String arrayList2String(ArrayList<Integer> list){
        StringBuilder output = new StringBuilder();
        for (int i=0; i<list.size(); i++){
            output.append(zeroPad(int2Hex(list.get(i))).toUpperCase());
        }
        return output.toString();
    }
    
    public static String array2String(int[] array){
        StringBuilder output = new StringBuilder();
        for (int i=0; i<array.length; i++){
            output.append(zeroPad(int2Hex(array[i])).toUpperCase());
        }
        return output.toString();
    }
    
    public static String[] int2Hex(int[] numArray){
        String[] hexArray = new String[numArray.length];
        for (int i=0; i<hexArray.length; i++)
            hexArray[i] = int2Hex(numArray[i]);
        return hexArray;
    }
    
    public static String int2Hex(int num){
        return Integer.toHexString(num);
    }
    
    public static String zeroPad(String hex){
        String result = hex;
        if (hex.length() == 1)
            result = "0"+hex;
        return result;
    }
    
    public static String String2HexString(String text){
        StringBuilder hex = new StringBuilder();
        for (int i=0; i<text.length(); i++){
            hex.append(AES.zeroPad(AES.int2Hex((int) text.charAt(i))));
        }
        return hex.toString();
    }
    
    public static String HexString2String(String hex){
        StringBuilder text = new StringBuilder();
        for (int i=0; i<hex.length(); i+=2){
            text.append((char) ((int) hex.charAt(i) + (int) hex.charAt(i+1)));
        }
        return text.toString();
    }
        
    public static int[] hex2int(String hex){
        int index = 0;
        int[] hexArray = new int[hex.length()/2];
        for (int i=0; i<hex.length(); i+=2){
            hexArray[index++] = hex2Int(new StringBuilder().append(hex.charAt(i)).append(hex.charAt(i+1)).toString());
        }
        printArray(hexArray);        
        
        return hexArray;
    }       
            
    public static ArrayList<Integer> hex2Integer(String hex){
        ArrayList<Integer> hexArray = new ArrayList<>(hex.length()/2);
        for (int i=0; i<hex.length(); i+=2){
            hexArray.add(hex2Int(new StringBuilder().append(hex.charAt(i)).append(hex.charAt(i+1)).toString()));
        }
        printArray(hexArray);        
        
        return hexArray;
    }
}
