import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;

/**
 * Tools for linear cryptanalysis of SPN
 * 
 * @author Slava Chernyak
 */
public class SpnLinearCryptanalysis {

  /**
   * Generate random plain/ciphertext pairs via the SPN cipher with the given
   * round keys
   * 
   * @param pairs
   *          Number of pairs to generate
   * @param roundKeys
   *          Round keys to use for the SPN cipher
   * @return List of plain/cipher sets (each set is 16 bits long)
   */
  public List<BitSet[]> generateRandomPairs(int pairs, BitSet[] roundKeys) {
    Random r = new Random();
    SpnImpl spn = new SpnImpl();
    List<BitSet[]> sets = new ArrayList<BitSet[]>();
    for (int i = 0; i < pairs; i++) {
      BitSet p = Util.toBitSet(r.nextInt(65536), 16);
      BitSet c = spn.SpnEncBlock(p, roundKeys);
      sets.add(new BitSet[] { p, c });
    }
    return sets;
  }

  /**
   * Backtrack across one s-box with a partial ciphertext and partial subkey
   * guess
   * 
   * @param partialc
   *          4 bit partial of the ciphertext
   * @param partialk
   *          4 bit partial of the subkey
   * @return
   */
  public BitSet backtrackPartialSubkeyGuess(BitSet partialc, BitSet partialk) {
    partialc = Util.copyBitSet(partialc, 4);
    partialc.xor(partialk);
    SpnImpl spn = new SpnImpl();
    BitSet U = spn.sBoxFunc(partialc, true);
    return U;
  }

  /**
   * Mount the linear cryptanalysis attack on the SPN cipher to recover 8 bits
   * of the final round key
   */
  public static void main(String[] args) {
    System.out.println("Running linear cryptanalysis on SPN....");
    // the expression to compute:
    // U_4,6 + U_4,8 + U_4,14 + U_4,16 + P_5 + P_7 + P_8 = 0

    // 0 - set the keys to be recovered - the partial
    // subkey bits that will be found are *2*4 in the last
    // round.
    BitSet[] roundKeys = new BitSet[] { Util.toBitSet(0x1234, 16),
        Util.toBitSet(0xDEAD, 16), Util.toBitSet(0x5678, 16),
        Util.toBitSet(0xACE1, 16), Util.toBitSet(0xFEED, 16), };

    // 1 - generate 10000 pairs
    int pairct = 10000;

    SpnLinearCryptanalysis slc = new SpnLinearCryptanalysis();
    List<BitSet[]> pairs = slc.generateRandomPairs(pairct, roundKeys);

    // 2 - for each pair, we perform the attack
    int[] counts = new int[256];
    for (int i = 0; i < counts.length; i++) {
      counts[i] = 0;
    }
    int count = 0;
    for (BitSet[] pair : pairs) {
      if (count++ % (pairct / 100) == 0) {
        System.out.print(((int) (count / ((double) pairct) * 100)) + "%\n");
      }
      BitSet p = pair[0];
      BitSet c = pair[1];

      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
          // This is the partial subkey guess for key bits 4 to 8
          BitSet partialSubkeyA = Util.toBitSet(i, 4);

          // This is the partial subkey guess for key bits 12 to 16
          BitSet partialSubkeyB = Util.toBitSet(j, 4);

          BitSet guessKeySet = Util.concatenate(partialSubkeyA, 4,
              partialSubkeyB, 4);
          int guessKey = Util.toInteger(guessKeySet, 8);

          // Backtrack to find U-bits 4 to 8
          BitSet partialCipherA = c.get(4, 8);
          BitSet UA = slc.backtrackPartialSubkeyGuess(partialCipherA,
              partialSubkeyA);

          // Backtrack to find U-bits 12-16
          BitSet partialCipherB = c.get(12, 16);
          BitSet UB = slc.backtrackPartialSubkeyGuess(partialCipherB,
              partialSubkeyB);

          // 4 - compute the linear/affine expression
          // U_4,6 + U_4,8 + U_4,14 + U_4,16 + P_5 + P_7 + P_8 = 0
          boolean lhs = UA.get(1) ^ UA.get(3) ^ UB.get(1) ^ UB.get(3)
              ^ p.get(4) ^ p.get(6) ^ p.get(7);
          // increment if the above expression holds
          if (lhs == false)
            counts[guessKey]++;
        }
      }
    }

    // 5 - determine the biases
    double[] bias = new double[counts.length];
    for (int i = 0; i < counts.length; i++) {
      bias[i] = Math.abs(counts[i] - (pairct / 2)) / ((double) pairct);
    }

    // 6 - print the results
    int maxi = 0;
    int maxj = 0;
    double maxbias = 0;

    System.out.println();
    System.out.println("Partial subkey bits : bias");
    for (int i = 0; i < 16; i++) {
      for (int j = 0; j < 16; j++) {
        int idx = i * 16 + j;
        System.out.print(Integer.toHexString(i));
        System.out.print(" " + Integer.toHexString(j));
        System.out.println(":\t" + bias[idx]);

        if (bias[idx] > maxbias) {
          maxbias = bias[idx];
          maxi = i;
          maxj = j;
        }
      }
    }

    System.out.println();
    System.out.println();
    System.out.println("Best candidate partial subkey is "
        + Integer.toHexString(maxi) + " " + Integer.toHexString(maxj)
        + " with bias " + maxbias);
  }
}
