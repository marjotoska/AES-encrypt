package aes;

import static aes.AES.arrayList2String;
import static aes.AES.convertIntegers;
import static aes.AES.printArray;
import static aes.AES.xorBlock;
import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author Emiljan Dusha
 */
public class ECB192 extends AES{
    
    final private int NUM_ROUNDS = 12;
    final private int KEY_BLOCK = 24;
    
    
    @Override
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

            for (int i=0; i<4; i++){
                keyArray[c] = keyArray[c-KEY_BLOCK] ^ wordSegment[i];
                c++;
            }
            
          
        }
        return keyArray;
    }
    
//    protected String encryptRoutine1(int[] message, int[] key, boolean debug){
//        int[] encrypted = new int[message.length];
//        int[] subbed, shifted, mixed;
//        
//        if (debug){
//            System.out.println("Starting plaintext");
//            printArray(message);
//        }
//        
//        encrypted = xorBlock(message, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
//        if (debug){
//            System.out.println("Starting key");
//            printArray(Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
//            System.out.println("After first XOR");
//            printArray(encrypted);
//            System.out.println("");
//        }
//        
//        for (int round=0; round<NUM_ROUNDS-1; round++){
//            
//            subbed = SubBytes(encrypted);
//            if (debug){
//                System.out.println("After Sub on round "+(round+1));
//                printArray(subbed);
//            }
//            
//            shifted = ShiftRows(subbed);
//            if (debug){
//                System.out.println("After Shift on round "+(round+1));
//                printArray(shifted);
//            }
//            
//            mixed = MixColumns(shifted);
//            if (debug){
//                System.out.println("After Mix on round "+(round+1));
//                printArray(mixed);
//            }
//            
//            encrypted = xorBlock(mixed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
//            if (debug){
//                System.out.println("Key for round "+(round+1));
//                printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round+MESSAGE_BLOCK, MESSAGE_BLOCK*round+32));
//                System.out.println("After XOR for round "+(round+1));
//                printArray(encrypted);
//                System.out.println("\n");
//            }
//        }
//        
//        subbed = SubBytes(encrypted);
//        if (debug){
//            System.out.println("After final Sub");
//            printArray(subbed);
//        }
//                
//        shifted = ShiftRows(subbed);
//        if (debug){
//            System.out.println("After final Shift");
//            printArray(shifted);
//        }
//        
//        encrypted = xorBlock(shifted, Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
//        if (debug){
//            System.out.println("Final key");
//            printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*(NUM_ROUNDS-1)+MESSAGE_BLOCK, MESSAGE_BLOCK*(NUM_ROUNDS-1)+32));
//        }
//        
//        if (debug){
//           System.out.println("Final Cipher text");
//           System.out.println(array2String(encrypted));
//       }
//        
//        return array2String(encrypted);
//    }
   
    @Override
    protected String encryptRoutine(ArrayList<Integer> message, int[] key, boolean debug){
        ArrayList<Integer> cipherText = new ArrayList<>(message.size());
        
        int[] subbed, shifted, mixed;
        int[] messageBlock = new int[16];
        int[] encryptedBlock = new int[16];
        
        if (message.size() < 16){
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
            messageBlock = convertIntegers(message);
            
            if (debug){
                    System.out.println("Starting plaintextaaa");
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
    
    @Override
    protected String decryptRoutine(int[] cipher, int[] key, boolean debug){
        int[] decrypted = new int[cipher.length];
        int[] subbed, shifted, mixed;
        
        if (debug){
            System.out.println("Starting Ciphertext");
            printArray(cipher);
        }
        
        decrypted = xorBlock(cipher, Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
        if (debug){
            System.out.println("Starting key");
            printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*NUM_ROUNDS, MESSAGE_BLOCK*(NUM_ROUNDS+1)));
            System.out.println("After first XOR");
            printArray(decrypted);
            System.out.println("");
        }
        
        shifted = invShiftRows(decrypted);
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
            decrypted = xorBlock(subbed, Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
            if (debug){
                System.out.println("Key for round "+(round+1));
                printArray(Arrays.copyOfRange(key, MESSAGE_BLOCK*round, MESSAGE_BLOCK*(round+1)));
                System.out.println("After XOR for round "+(round+1));
                printArray(decrypted);
            }
            
            mixed = invMixColumns(decrypted);
            if (debug){
                System.out.println("After Unmix on round "+(round+1));
                printArray(mixed);
            }
            
            shifted = invShiftRows(mixed);
            if (debug){
                System.out.println("After Unshift on round "+(round+1));
                printArray(shifted);
                System.out.println("\n");
            }
            
            subbed = invSubBytes(shifted);
            if (debug){
                System.out.println("After Unsub on round "+(round+1));
                printArray(subbed);
            }
        }
        
        decrypted = xorBlock(subbed, Arrays.copyOfRange(key, 0, MESSAGE_BLOCK));
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
    
}
