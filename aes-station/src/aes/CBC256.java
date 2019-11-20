package aes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Emiljan Dusha
 */
public class CBC256 extends AES{
    
    final private int NUM_ROUNDS = 14;
    final private int KEY_BLOCK = 32;    
    
    
    public int[] KeySchedule(int[] masterKey){
        int[] keyArray = new int[MESSAGE_BLOCK*(NUM_ROUNDS+1)];
        int c = KEY_BLOCK;
        int rconIndex = 0;
        System.arraycopy(masterKey, 0, keyArray, 0, masterKey.length);
        int[] wordSegment = new int[4];
                
        while (c < MESSAGE_BLOCK*(NUM_ROUNDS+1)){
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

            if (c % KEY_BLOCK == 16)
                wordSegment = SubBytes(wordSegment);
            
            for (int i=0; i<4; i++){
                keyArray[c] = keyArray[c-KEY_BLOCK] ^ wordSegment[i];
                c++;
            }
            
        }
        return keyArray;
    }
    
    protected String encryptRoutine(ArrayList<Integer> message, int[] key, int[] iv, boolean debug){
        ArrayList<Integer> cipherText = new ArrayList<>(Collections.nCopies(message.size(), 0));
        
        int[] subbed, shifted, mixed, init;
        int[] messageBlock = new int[16];
        int[] encryptedBlock = new int[16];
        
        while (message.size() % 16 != 0)
            message.add(0);
        
        
        double blocks = message.size()/(16*1.0);
        
        if (debug){
            System.out.println("Starting plaintext");
            printArray(message);
        }
        
        for (int block = 0; block < blocks; block++){
            messageBlock = convertIntegers(message.subList(block*16, block*16+16));
            
            if (debug){
                System.out.println("Current Block");
                printArray(messageBlock);
            }

            if (block == 0){
                init = xorBlock(messageBlock, iv);
                if (debug){
                    System.out.println("Initialization vector");
                    printArray(iv);
                    System.out.println("After XOR with iv");
                    printArray(init);
                }
            }
            else{
                encryptedBlock = convertIntegers(cipherText.subList((block-1)*16, block*16));
                init = xorBlock(messageBlock, encryptedBlock);
                if (debug){
                    System.out.println("Previous cipher block");
                    printArray(encryptedBlock);
                }
            }
            
            
            encryptedBlock = xorBlock(init, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
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

                printArray(key);
                encryptedBlock = xorBlock(mixed, Arrays.copyOfRange(key, MESSAGE_BLOCK*(round+1), MESSAGE_BLOCK*(round+1)+16));
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

            encryptedBlock = xorBlock(shifted, Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
            if (debug){
                System.out.println("Final key");
                printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
                System.out.println("Cipher Block");
                printArray(encryptedBlock);
                System.out.println("\n\n");
            }
            
            for (int i=0; i<encryptedBlock.length; i++)
                cipherText.set(block*16+i, encryptedBlock[i]);
        }
        
       if (debug){
           System.out.println("Final Cipher text");
           System.out.println(arrayList2String(cipherText));
       }
        
        return arrayList2String(cipherText);
    }
    
    protected String decryptRoutine(ArrayList<Integer> cipher, int[] key, int[] iv, boolean debug){
        ArrayList<Integer> plainText = new ArrayList<>(Collections.nCopies(cipher.size(), 0));

        int[] subbed, shifted, mixed, init;
        int[] cipherBlock = new int[16];
        int[] decryptedBlock = new int[16];

        while (cipher.size() % 16 != 0)
            cipher.add(0);

        double blocks = cipher.size()/(16*1.0);

        if (debug){
            System.out.println("Starting Ciphertext");
            printArray(cipher);
        }

        for (int block = 0; block < blocks; block++) {
            cipherBlock = convertIntegers(cipher.subList(block*16, block*16+16));

            if (debug){
                System.out.println("Current Block");
                printArray(cipherBlock);
            }

            decryptedBlock = xorBlock(cipherBlock, Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
            if (debug){
                System.out.println("Starting key");
                printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
                System.out.println("After first XOR");
                printArray(decryptedBlock);
                System.out.println("");
            }

            shifted = invShiftRows(decryptedBlock);
            if (debug){
                System.out.println("After first Shift");
                printArray(shifted);
            }

            subbed = invSubBytes(shifted);
            if (debug){
                System.out.println("After first Sub");
                printArray(subbed);
            }

            for (int round=NUM_ROUNDS-1; round>0; round--){
                decryptedBlock = xorBlock(subbed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
                if (debug){
                    System.out.println("Key for round "+(round+1));
                    printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
                    System.out.println("After XOR for round "+(round+1));
                    printArray(decryptedBlock);
                }

                mixed = invMixColumns(decryptedBlock);
                if (debug){
                    System.out.println("After Unmix on round "+(round+1));
                    printArray(mixed);
                }

                shifted = invShiftRows(mixed);
                if (debug){
                    System.out.println("After Unshift on round "+(round+1));
                    printArray(shifted);
                }

                subbed = invSubBytes(shifted);
                if (debug){
                    System.out.println("After Unsub on round "+(round+1));
                    printArray(subbed);
                    System.out.println("\n");
                }
            }

            decryptedBlock = xorBlock(subbed, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
            if (debug){
                System.out.println("Final key");
                printArray(Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
                System.out.println("Final Plaintext");
                printArray(decryptedBlock);
            }

            if (block == 0){
                init = xorBlock(decryptedBlock, iv);
                if (debug){
                        System.out.println("Initialization vector");
                        printArray(iv);
                        System.out.println("After XOR with iv");
                        printArray(init);
                    }
            }
            else{
                cipherBlock = convertIntegers(cipher.subList((block-1)*16, block*16));
                init = xorBlock(cipherBlock, decryptedBlock);
                if (debug){
                    System.out.println("Previous cipher block");
                    printArray(cipherBlock);
                }
            }
            for (int i=0; i<init.length; i++)
                plainText.set(block*16+i, init[i]);
        }

        if (debug){
            System.out.println("Final Plain text");
            System.out.println(arrayList2String(plainText));
        }
        
        return arrayList2String(plainText);
    }
    
}
