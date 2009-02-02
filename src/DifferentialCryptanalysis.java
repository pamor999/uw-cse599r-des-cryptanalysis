import java.io.IOException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;

/**
 * Tools for Differential Cryptanalysis of DES
 * 
 * @author Sourav Sen Gupta
 */
public class DifferentialCryptanalysis {

  public static void main(String[] args) {
    DesDifferentialAttack4Round();
    // PrintNSforAll();
  }

  /**
   * Prints the Differential Tables for all Sboxes
   */
  public static void PrintNSforAll() {

    for (int sbox = 0; sbox < 8; sbox++) {
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
   * Defines the NS function in lines of Biham Shamir
   * "Differential Cyptanalysis of DES like Cryptosystems"
   * 
   * @param sbox
   *          identifies the S-Box (1 to 8)
   * @param alpha
   *          represents a value between 0 and 63 selecting bits of the input
   *          difference
   * @param beta
   *          represents a value between 0 and 15 selecting bits of the output
   *          difference
   * @return The number of times the pair 'alpha -> beta' occurs (0 to 64)
   */
  public static int BihamShamirNS(int sbox, BitSet alpha, BitSet beta) {
    int count = 0;
    BitSet input = new BitSet(6);
    input.set(0, 5, false);

    for (int i = 0; i < 64; i++) {
      BitSet current = (BitSet) input.clone();
      DesImpl des = new DesImpl();

      // compute Y
      BitSet Y = des.SBoxSingle(sbox, current);

      // compute Y*
      current = (BitSet) input.clone();
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
   * 
   * @param pairs
   *          Number of pairs to generate
   * @param key
   *          the DES key
   * @param numRounds
   *          the number of DES rounds
   * @return List of plain/cipher sets (each set is 16 bits long)
   */
  public static List<BitSet[]> generateRandomPairs(int pairs, BitSet key,
      int numRounds) {
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

      // first pair
      BitSet p_one = Util.concatenate(p12, 32, p34, 32);
      BitSet c_one = des.DesEncBlock(p_one, key, numRounds);

      // delta_p = 20 00 00 00 00 00 00 00
      BitSet delta_pL1 = Util.toBitSet(0x2000, 16);
      BitSet delta_pL2 = Util.toBitSet(0x0000, 16);
      BitSet delta_pR1 = Util.toBitSet(0x0000, 16);
      BitSet delta_pR2 = Util.toBitSet(0x0000, 16);
      BitSet delta_pL = Util.concatenate(delta_pL1, 16, delta_pL2, 16);
      BitSet delta_pR = Util.concatenate(delta_pR1, 16, delta_pR2, 16);

      BitSet delta_p = Util.concatenate(delta_pL, 32, delta_pR, 32);

      // second pair
      BitSet p_two = Util.copyBitSet(p_one, 64);
      p_two.xor(delta_p);
      BitSet c_two = des.DesEncBlock(p_two, key, numRounds);

      BitSet delta_CR = c_one.get(32, 64);
      delta_CR.xor(c_two.get(32, 64));

      sets.add(new BitSet[] { c_one, c_two });

    }
    return sets;
  }


  /**
 * 
 */
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
    int numPairs = 16;
    
    // print info 
    System.out.println("4-round DES Linear Cryptanalysis.");
    System.out.println("Using " + numPairs + " pairs.");
    System.out.println("****************");
    System.out.println("Using Key:");
    Util.printBitSet(key, 64);
    System.out.println("****************");
    System.out.println("Real round 4 key:");
    for (int i = 0; i < 8; i++){
      BitSet K4_S = K4.get(6*i, 6*(i+1));
      System.out.print("\tS-Box " + (i+1) + ":\t");
      System.out.print(Integer.toHexString(Util.toInteger(K4_S, 6)) + " ");
      System.out.println();
    }
    System.out.println("****************");
    System.out.println("Press Enter to run linear attack...");
    try {
      System.in.read();
    } catch(IOException exn) {
      
    }
    
    // generate the pairs
    System.out.println("");
    System.out.println("Generating " + numPairs + " pairs...");
    List<BitSet[]> pairs = generateRandomPairs(numPairs, key, numRounds);
    System.out.println("Good pairs: " + pairs.size());

    int[][] counts = new int[8][64];
    for (int k = 0; k < 8; k++){
	    for (int i = 0; i < counts.length; i++) {
	      counts[k][i] = 0;
	    }
    }
    
    for (BitSet[] pair : pairs) {
//      if (count++ % (numPairs / 100) == 0) {
//        System.out.print(((int) (count / ((double) numPairs) * 100)) + "%\n");
//      }

      BitSet C1L = pair[0].get(0, 32);
      BitSet C1R = pair[0].get(32, 64);
      BitSet C2L = pair[1].get(0, 32);
      BitSet C2R = pair[1].get(32, 64);

      // calculate the input of S-Boxes - Round 4
      BitSet W1 = des.E(C1R);
      BitSet W2 = des.E(C2R);
      
      // calculate the output of S-Boxes - Round 4
      BitSet delta_D = Util.copyBitSet(C1L, 32);
      delta_D.xor(C2L);
      BitSet delta_Y = des.PermuteCInv(delta_D);
      
      
      for (int sbox = 0; sbox < 8; sbox++){
		  for (int i = 0; i < 64; i++) {
		    // guess the key for Sbox
		    BitSet partialSubkeyGuess = Util.toBitSet(i, 6);
		    
		    // inputs to the S-Box
		    BitSet X1 = W1.get(6*sbox,6*(sbox+1));
		    X1.xor(partialSubkeyGuess);
		    BitSet X2 = W2.get(6*sbox,6*(sbox+1));
		    X2.xor(partialSubkeyGuess);
		    
		    // calculate predicted output of S-Box
		    BitSet pred_Y1 = des.SBoxSingle(sbox, X1);
		    BitSet pred_Y2 = des.SBoxSingle(sbox, X2);
		    
		    BitSet pred_deltaY = Util.copyBitSet(pred_Y1, 4);
		    pred_deltaY.xor(pred_Y2);
		    
		    // check for a match with original delta_Y
		    BitSet orig_deltaY = delta_Y.get(4*sbox,8*(sbox+1));
		    
		    boolean lhs = Util.equalsBitSet(pred_deltaY, orig_deltaY, 4);
		    
		    if (lhs == true) {
		      counts[sbox][i]++;
		    }
		  }
      	}
    }

    // 5 - determine the probabilities
    double[][] prob = new double[8][64];
    for (int k = 0; k < 8; k++){
	    for (int i = 0; i < 64; i++) {
	      prob[k][i] = counts[k][i] / ((double) numPairs);
	    }
    }

    // 6 - print the results
    
    System.out.println();
    System.out.println();
    System.out.println("Best candidate subkeys are");
    
    
    for (int k = 0; k < 8; k++){
    	int maxi = 0;
        double maxprob = 0;
        
	    System.out.println();
	    System.out.println("Partial subkey bits : probability");
	    for (int i = 0; i < 64; i++) {
	
	      System.out.print(Integer.toHexString(i));
	      System.out.println(":\t" + prob[k][i]);
	
	      if (prob[k][i] >= maxprob) {
	        maxprob = prob[k][i];
	        maxi = i;
	      }
	    }
	    
	    System.out.println();
	    System.out.println();
	    System.out.println("S-Box " + (k+1) + " : " + Integer.toHexString(maxi) + " with bias " + maxprob);
	    System.out.println();
	    System.out.println();
	    
    }

  }
}
