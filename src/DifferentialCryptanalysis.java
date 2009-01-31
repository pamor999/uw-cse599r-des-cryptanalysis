import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;


public class DifferentialCryptanalysis {
  
  public static void main(String[] args) {
	  DesDifferentialAttack4Round();
	  //PrintNSforAll();
  }	
	

  // Prints the Differential Tables for all Sboxes
  /**
  * @param args
  */
  public static void PrintNSforAll(){
	
	for (int sbox = 0 ; sbox < 8; sbox++) {
      System.out.println("SBOX: " + (sbox + 1));
      
      
      BitSet alpha = new BitSet(6);
      alpha.set(0, 5, false);
      BitSet beta = new BitSet(4);
      beta.set(0, 3, false);
      
      for (int i = 0; i < 16; i++) {
        System.out.print("\t" + i);
      }
      System.out.println();
      
      for (int i = 0; i < 64; i++) {
        System.out.print(i + ":\t");
        for (int j = 0; j < 16; j++) {
          int ns = BihamShamirNS(sbox, alpha, beta);
          
          Util.increment(beta, 4);          
          System.out.print(ns + "\t");          
        }        
        Util.increment(alpha, 6);        
        System.out.println();        
      }
      System.out.println();
      System.out.println();
      
    }    
        
  }
  
  
  /**
   * Defines the NS function in lines of Biham Shamir "Differential Cyptanalysis of DES like Cryptosystems"
   * @param sbox identifies the S-Box (1 to 8)
   * @param alpha represents a value between 0 and 63 selecting bits of the input difference
   * @param beta represents a value between 0 and 15 selecting bits of the output difference
   * @return The number of times the pair 'alpha -> beta' occurs (0 to 64)
   */
  public static int BihamShamirNS(int sbox, BitSet alpha, BitSet beta) {
    int count = 0;
    BitSet input = new BitSet(6);
    input.set(0, 5, false);
    
    for (int i = 0; i < 64; i++) {
      BitSet current = (BitSet)input.clone();
      DesImpl des = new DesImpl();
      
      //compute Y
      BitSet Y = des.SBoxSingle(sbox, current);
        
    	
      // compute Y*
      current = (BitSet)input.clone();
      current.xor(alpha);
      BitSet Ystar = des.SBoxSingle(sbox, current);
      
      // equality
      Y.xor(Ystar);
      if (Y.equals(beta)) {
        count++;
      }

      // increment the input for the next round
      Util.increment(input, 6);
    }
    
    return count;
  }

  
  
  
  
  /**
   * Generate random plain/ciphertext pairs via the DES cipher with the given
   * key and number of rounds
   * @param pairs Number of pairs to generate
   * @param key the DES key
   * @param numRounds the number of DES rounds
   * @return List of plain/cipher sets (each set is 16 bits long)
   */
  public static List<BitSet[]> generateRandomPairs(int pairs, BitSet key, int numRounds) {
    Random r = new Random();
    DesImpl des = new DesImpl();
    List<BitSet[]> sets = new ArrayList<BitSet[]>();
    for (int i = 0; i < pairs; i++) {
      // four bloks of 16 bits each
      BitSet p1 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet p2 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet p3 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet p4 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet p12 = Util.concatenate(p1, 16, p2, 16);
      BitSet p34 = Util.concatenate(p3, 16, p4, 16);
      
      //first pair
      BitSet p_one = Util.concatenate(p12, 32, p34, 32);
      BitSet c_one = des.DesEncBlock(p_one, key, numRounds);
      
      //delta_p = 00 80 82 00 60 00 00 00
      BitSet delta_p1 = Util.toBitSet(0x20000000,32);
      BitSet delta_p2 = Util.toBitSet(0x00000000,32);
      BitSet delta_p = Util.concatenate(delta_p1, 32, delta_p2, 32);
            
      //second pair
      BitSet p_two = Util.copyBitSet(p_one, 64);
      p_two.xor(delta_p);
      BitSet c_two = des.DesEncBlock(p_two, key, numRounds);
            
      sets.add(new BitSet[]{c_one, c_two});
    }
    return sets;
  }
  
 
  
  public static void DesDifferentialAttack4Round() {
	    // do analysis for 4-round DES
	    int numRounds = 4;
	    
	    // set the key
	    BitSet key1 = Util.toBitSet(0x1234, 16);
	    BitSet key2 = Util.toBitSet(0x8743, 16);
	    BitSet key3 = Util.toBitSet(0xFAC3, 16);
	    BitSet key4 = Util.toBitSet(0xECAB, 16);
	    BitSet key12 = Util.concatenate(key1, 16, key2, 16);
	    BitSet key34 = Util.concatenate(key3, 16, key4, 16);
	    BitSet key = Util.concatenate(key12, 32, key34, 32);
	    
	    // print the actual key bits
	    DesImpl des = new DesImpl();
	    BitSet K4 = des.KeySchedule(key, 4);
	    
	    //BitSet K4_S1 = K4.get(0, 6);
	    System.out.println("actual key is " + 
	    		Integer.toHexString(Util.toInteger(K4, 64)));
	    
	    // generate the pairs
	    int numPairs = 1000;
	    System.out.print("Generating " + numPairs + " pairs...");
	    List<BitSet[]> pairs = generateRandomPairs(numPairs, key, numRounds);
	    System.out.println("done");
	    
	    int[] counts = new int[64];
	    for(int i = 0; i < counts.length; i++) {
	        counts[i] = 0;
	    }
	    int count = 0;
	    for (BitSet[] pair : pairs) {
	        if (count++ % (numPairs/100) == 0) {
	          System.out.print(((int) (count / ((double)numPairs) * 100))+ "%\n");
	        }

	        BitSet C1L = pair[0].get(0, 32);
	        BitSet C1R = pair[0].get(32, 64);
	        BitSet C2L = pair[1].get(0, 32);
	        BitSet C2R = pair[1].get(32, 64);
	        
		    for (int i = 0; i < 64; i++) {
		    	// guess the key for Sbox 1 - we guess for S-Box 1
		    	// because it is the only sbox affecting  CL[15] in the 
		    	// expression for a 3-round DES.
		    	BitSet partialSubkeyGuess = Util.toBitSet(i, 6);
		    	// pad it 
				BitSet subKeyGuess = Util.concatenate(Util.toBitSet(0, 24), 24, partialSubkeyGuess, 6);
		    	subKeyGuess = Util.concatenate(subKeyGuess, 30, Util.toBitSet(0, 18), 18);
		    	
		    	// now invert the final round with it
		    	BitSet C1L_prev = Util.copyBitSet(C1L,32); 
		    	BitSet C1R_prev = Util.copyBitSet(C1R,32);
		    	BitSet C2L_prev = Util.copyBitSet(C2L,32);
		    	BitSet C2R_prev = Util.copyBitSet(C2R,32);
		    	
		    	C1L_prev.xor(des.Feistel(C1R_prev, subKeyGuess));
		    	C2L_prev.xor(des.Feistel(C2R_prev, subKeyGuess));
		    	
		    	// swap the result to undo the last Tau
		    	BitSet temp1 = C1L_prev;
		    	C1L_prev = C1R_prev;
		    	C1R_prev = temp1;
	    		
		    	BitSet temp2 = C2L_prev;
		    	C2L_prev = C2R_prev;
		    	C2R_prev = temp2;
	    		
		    	// compute the 3-round expression:
		    	BitSet delta_U4R = Util.copyBitSet(C1R_prev, 32);
		        delta_U4R.xor(C2R_prev);
		        
		        BitSet check = Util.toBitSet(0x00008000,32);
		    	BitSet bits = delta_U4R.get(0,32);
		    	System.out.print(Util.toInteger(bits, 32));
		        boolean lhs = delta_U4R.get(16); //Util.equalsBitSet(bits, check, 32);
	            
	            if (lhs == true) counts[i]++;	     
		    }
	    }
	    
	    // 5 - determine the biases 
	    double[] prob = new double[counts.length];
	    for (int i = 0; i < counts.length; i++) {
			prob[i] = counts[i] / ((double)numPairs);    		
	    }
	    
	    // 6 - print the results
	    int maxi = 0;
	    double maxprob = 0;
	    
	    System.out.println();
	    System.out.println("Partial subkey bits : bias");
	    for (int i = 0; i < prob.length; i++) {
					    			
	    System.out.print(Integer.toHexString(i));
	    System.out.println(":\t" + prob[i]);
	    
		    if (prob[i] > maxprob) {
		      maxprob = prob[i];
		      maxi = i;
		    }
	    }
	    
	    System.out.println();
	    System.out.println();
	    System.out.println("Best candidate partial subkey is " +
	        Integer.toHexString(maxi) + " with bias " + maxprob);
	    
	  }
  
}
