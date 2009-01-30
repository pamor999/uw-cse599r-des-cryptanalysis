import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;

/**
 * Tools for linear cryptanalysis of DES
 * 
 * @author Slava Chernyak
 */
public class LinearCryptanalysis {

  /**
   * Run any of the following commented out blocks
   * 
   * @param args
   */
  public static void main(String[] args) {
    DesLinearAttack4Round();
    // PrintNSForAll();
    // MatsuiEqn5Distribution();
    // testFinalRound();
  }

  /**
   * Print the matsui NS values for all DES sboxes
   */
  public static void PrintNSForAll() {
    int max = 0;
    int maxAlpha = -1;
    int maxBeta = -1;

    for (int sbox = 0; sbox < 8; sbox++) {
      System.out.println("SBOX: " + (sbox + 1));

      BitSet alpha = new BitSet(6);
      BitSet beta = new BitSet(4);

      for (int i = 1; i < 16; i++) {
        System.out.print("\t" + i);
      }
      System.out.println();

      // Reset the max initial value for each SBox
      max = 0;

      Util.increment(alpha, 6);
      for (int i = 1; i < 64; i++) {
        System.out.print(i + ":\t");
        Util.increment(beta, 4);
        for (int j = 1; j < 16; j++) {
          int ns = MatsuiNS(sbox, alpha, beta);
          int delta = ns - 32;

          if (Math.abs(delta) > max) {
            max = Math.abs(delta);
            maxAlpha = Util.toInteger(alpha, 6);
            maxBeta = Util.toInteger(beta, 4);
          }
          Util.increment(beta, 4);
          System.out.print(delta + "\t");
        }
        Util.increment(alpha, 6);
        System.out.println();
      }
      System.out.println();

      System.out.println("Max |NS| for SBox " + (sbox + 1) + " is " + max
          + " with alpha " + maxAlpha + " and beta " + maxBeta);
      System.out.println();
      System.out.println();
    }
  }

  /**
   * Defines the NS function as in Matsui
   * "Linear Cryptanalysis Method for DES cipher"
   * 
   * @param sbox
   *          identifies the S-Box (1 to 8)
   * @param alpha
   *          repesents a value between 0 and 63 selecting bits of the input to
   *          be xor-ed
   * @param beta
   *          represents a value between 0 and 15 selecting bits of the output
   *          to be xor-ed
   * @return The number of times the values of the xored expressoins coincide (0
   *         to 64)
   */
  public static int MatsuiNS(int sbox, BitSet alpha, BitSet beta) {
    int count = 0;
    BitSet input = new BitSet(6);
    input.set(0, 5, false);

    for (int i = 0; i < 64; i++) {
      // compute the LHS of NS
      BitSet current = (BitSet) input.clone();
      current.and(alpha);
      boolean leftResult = Util.DirectSum(current, 6);

      // compute the RHS of NS
      current = (BitSet) input.clone();
      DesImpl des = new DesImpl();
      current = des.SBoxSingle(sbox, current);
      current.and(beta);
      boolean rightResult = Util.DirectSum(current, 4);

      // equality
      if (leftResult == rightResult) {
        count++;
      }

      // increment the input for the next round
      Util.increment(input, 6);
    }

    return count;
  }

  /**
   * Measures the probability of holding of Matsui eqn 5 over a set of random
   * inputs
   */
  public static void MatsuiEqn5Distribution() {
    BitSet k1 = Util.toBitSet(0xFEEEED, 24);
    BitSet k2 = Util.toBitSet(0x123456, 24);
    BitSet K = Util.concatenate(k1, 24, k2, 24);

    // generate random X-input values
    Random r = new Random();
    DesImpl des = new DesImpl();

    int numXs = 10000;
    int count = 0;
    for (int i = 0; i < numXs; i++) {
      BitSet x1 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet x2 = Util.toBitSet(r.nextInt(65536), 16);
      BitSet X = Util.concatenate(x1, 16, x2, 16);

      BitSet F = des.Feistel(X, K);

      // now compute eqn 5
      // X[15] + F(X,K)[7, 18, 24, 29] = K[22]
      // probability of holding should be ~ 0.19
      boolean lhs = X.get(31 - 15) ^ F.get(31 - 7) ^ F.get(31 - 18)
          ^ F.get(31 - 24) ^ F.get(31 - 29);
      if (lhs == false)
        count++;
    }

    System.out.println("Eqn5 frequency of holding:");
    System.out.println(count / ((double) numXs));

  }

  /**
   * Do some testing of un-doing the last round of DES
   */
  public static void testFinalRound() {
    BitSet k1 = Util.toBitSet(0xFEEEED, 24);
    BitSet k2 = Util.toBitSet(0x123456, 24);
    BitSet K = Util.concatenate(k1, 24, k2, 24);

    BitSet r1 = Util.toBitSet(0xDEAD, 16);
    BitSet r2 = Util.toBitSet(0xBEEF, 16);
    BitSet R = Util.concatenate(r1, 16, r2, 16);
    BitSet CR = Util.copyBitSet(R, 32);

    DesImpl des = new DesImpl();
    BitSet F = des.PermuteCInv(des.Feistel(R, K));

    // test the following: a partial subkey guess of the
    // same first 6 bits as the key should make the results
    // of s-box 1 identical. The 4 resultant bits of s-box
    // 1 get propogated to bits 16, 7, 20, 21 of the feistel
    // result

    BitSet k1guess = Util.toBitSet(0xFC0000, 24);
    BitSet k2guess = Util.toBitSet(0x000006, 24);
    BitSet Kguess = Util.concatenate(k1guess, 24, k2guess, 24);

    BitSet Fguess = des.PermuteCInv(des.Feistel(CR, Kguess));

    System.out.println("F, and F guess");
    printBitSet(F, 32, 32);
    printBitSet(Fguess, 32, 32);

    // now a slightly more involved test - we encrypt
    // a block with 4 rounds, then invert the last round
    // and compare to a 3-round encryption

    // set the key
    BitSet key1 = Util.toBitSet(0x1234, 16);
    BitSet key2 = Util.toBitSet(0xFFFF, 16);
    BitSet key3 = Util.toBitSet(0xFFFF, 16);
    BitSet key4 = Util.toBitSet(0xF2FF, 16);
    BitSet key12 = Util.concatenate(key1, 16, key2, 16);
    BitSet key34 = Util.concatenate(key3, 16, key4, 16);
    BitSet key = Util.concatenate(key12, 32, key34, 32);

    // set the plaintext
    Random r = new Random();
    BitSet p1 = Util.toBitSet(r.nextInt(65536), 16);
    BitSet p2 = Util.toBitSet(r.nextInt(65536), 16);
    BitSet p3 = Util.toBitSet(r.nextInt(65536), 16);
    BitSet p4 = Util.toBitSet(r.nextInt(65536), 16);
    BitSet p12 = Util.concatenate(p1, 16, p2, 16);
    BitSet p34 = Util.concatenate(p3, 16, p4, 16);
    BitSet P = Util.concatenate(p12, 32, p34, 32);

    BitSet C4 = des.DesEncBlock(P, key, 4);
    BitSet C3 = des.DesEncBlock(P, key, 3);
    BitSet K4 = des.KeySchedule(key, 4);

    // manually do the last round to verify
    BitSet C3L = C3.get(0, 32);
    BitSet C3R = C3.get(32, 64);
    // do tau
    BitSet C3Lt = Util.copyBitSet(C3R, 32);
    BitSet C3Rt = Util.copyBitSet(C3L, 32);

    C3Lt.xor(des.Feistel(C3Rt, K4));

    BitSet C4L = C4.get(0, 32);
    BitSet C4R = C4.get(32, 64);

    System.out.println("Ls");
    printBitSet(C3L, 32, 32);
    printBitSet(C4L, 32, 32);
    System.out.println("Rs");
    printBitSet(C3R, 32, 32);
    printBitSet(C4R, 32, 32);

    // undo the last round
    C4L.xor(des.Feistel(C4R, K4));
    // undone L of 4th round will be R of 3-round DES
    System.out.println("Ls");
    printBitSet(C3L, 32, 32);
    printBitSet(C4R, 32, 32);
    System.out.println("Rs");
    printBitSet(C3R, 32, 32);
    printBitSet(C4L, 32, 32);
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
      BitSet p = Util.concatenate(p12, 32, p34, 32);

      BitSet c = des.DesEncBlock(p, key, numRounds);
      sets.add(new BitSet[] { p, c });
    }
    return sets;
  }

  /**
   * Perform a full Linear attack on 4 round DES
   */
  public static void DesLinearAttack4Round() {
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

    BitSet K4_S1 = K4.get(0, 6);
    System.out.println("actual partial subkey is "
        + Integer.toHexString(Util.toInteger(K4_S1, 6)));

    // generate the pairs
    int numPairs = 1000;
    System.out.print("Generating " + numPairs + " pairs...");
    List<BitSet[]> pairs = generateRandomPairs(numPairs, key, numRounds);
    System.out.println("done");

    int[] counts = new int[64];
    for (int i = 0; i < counts.length; i++) {
      counts[i] = 0;
    }
    int count = 0;
    for (BitSet[] pair : pairs) {
      if (count++ % (numPairs / 100) == 0) {
        System.out.print(((int) (count / ((double) numPairs) * 100)) + "%\n");
      }

      BitSet PH = pair[0].get(0, 32);
      BitSet PL = pair[0].get(32, 64);
      BitSet CH = pair[1].get(0, 32); // L
      BitSet CL = pair[1].get(32, 64); // R

      for (int i = 0; i < 64; i++) {
        // guess the key for Sbox 1 - we guess for S-Box 1
        // because it is the only sbox affecting CL[15] in the
        // expression for a 3-round DES.
        BitSet partialSubkeyGuess = Util.toBitSet(i, 6);
        // pad it
        BitSet subKeyGuess = Util.concatenate(partialSubkeyGuess, 6, Util
            .toBitSet(0, 24), 24);
        subKeyGuess = Util.concatenate(subKeyGuess, 30, Util.toBitSet(0, 18),
            18);

        // now invert the final round with it
        BitSet CH_prev = Util.copyBitSet(CH, 32);
        BitSet CL_prev = Util.copyBitSet(CL, 32);

        CH_prev.xor(des.Feistel(CL_prev, subKeyGuess));
        // swap the result to undo the last Tau
        BitSet temp = CH_prev;
        CH_prev = CL_prev;
        CL_prev = temp;

        // compute the 3-round expression:
        // PH[7,18,25,29] + CH[7,18,24,29] + PL[15] + CL[15] = K1[22] + K3[22]
        // (=0)
        boolean lhs = PH.get(31 - 7) ^ PH.get(31 - 18) ^ PH.get(31 - 24)
            ^ PH.get(31 - 29) ^ CH_prev.get(31 - 7) ^ CH_prev.get(31 - 18)
            ^ CH_prev.get(31 - 24) ^ CH_prev.get(31 - 29) ^ PL.get(31 - 15)
            ^ CL_prev.get(31 - 15);

        if (lhs == false)
          counts[i]++;
      }
    }

    // 5 - determine the biases
    double[] bias = new double[counts.length];
    for (int i = 0; i < counts.length; i++) {
      bias[i] = Math.abs(counts[i] - (numPairs / 2)) / ((double) numPairs);
    }

    // 6 - print the results
    int maxi = 0;
    double maxbias = 0;

    System.out.println();
    System.out.println("Partial subkey bits : bias");
    for (int i = 0; i < bias.length; i++) {

      System.out.print(Integer.toHexString(i));
      System.out.println(":\t" + bias[i]);

      if (bias[i] > maxbias) {
        maxbias = bias[i];
        maxi = i;
      }
    }

    System.out.println();
    System.out.println();
    System.out.println("Best candidate partial subkey is "
        + Integer.toHexString(maxi) + " with bias " + maxbias);

  }

  public static void printBitSet(BitSet set, int lineLength, int setLength) {
    int ptr = 0;
    while (ptr < setLength) {
      System.out.print(set.get(ptr) ? "1" : "0");
      if (++ptr % lineLength == 0) {
        System.out.println();
      }
    }
  }
}
