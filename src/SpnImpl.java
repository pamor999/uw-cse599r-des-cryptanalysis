import java.util.BitSet;


public class SpnImpl {
  
  public static int[] SBOX = new int[]{ 0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7 };
  public static int[] SBOX_INV = new int[]{ 0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF, 0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5}; 
  
  /** Note that this permutation is an involution */
  public static int[] PERM = new int[]{ 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};
  
  /**
   * Perform S-BOX substitution on bit set s
   * @param s a 4-bit bit set
   * @return the result of the S-Box
   */
  public BitSet sBoxFunc(BitSet s, boolean inv) {
    int idx = Util.toInteger(s, 4);
    int result;
    if (inv) {
      result = SBOX_INV[idx];
    } else {
      result = SBOX[idx];     
    }
    return Util.toBitSet(result, 4);
  }
  
  /**
   * Perform the permutation of block s
   * @param s 16 bit block to permute
   * @return result of permutation
   */
  public BitSet Permute(BitSet s) {
    BitSet fromPerm = new BitSet(16);
    for (int i = 0; i < 16; i++) {
      fromPerm.set(PERM[i] - 1, s.get(i));
    }
    return fromPerm;
  }
  
  /**
   * Performs all the s-box substitutions on block s
   * @param s 16-bit block
   * @return the result of the substitutions 
   */
  public BitSet sBoxes(BitSet s, boolean inv) {
    BitSet result = new BitSet(16);
    for (int i = 0; i < 4; i++) {
      // compute each sbox
      BitSet toS = new BitSet(4);
      for (int j = 0; j < 4; j++) {
        toS.set(j, s.get(i * 4 + j));        
      }
      BitSet fromS = sBoxFunc(toS, inv);
      for (int j = 0; j < 4; j++) {
        result.set(i * 4 + j, fromS.get(j));
      }
    }
    return result;
  }
  
  /**
   * Performs one round of spn given the input block and round key k
   * @param s 16-bit input block
   * @param k 16-bit round key
   * @return Result of round
   */
  public BitSet SpnEncRound(BitSet s, BitSet k, boolean permute) {
    s.xor(k);
    s = sBoxes(s, false);
    if (permute)
      s = Permute(s);
    return s;
  }
  
  public BitSet SpnDecRound(BitSet s, BitSet k, boolean permute) {
    if (permute) 
      s = Permute(s);
    s = sBoxes(s, true);
    s.xor(k);
    return s;
  }
  
  /**
   * Encrypt a block p with the SPN cyper
   * round keys
   * @param p 16-bit plaintext block
   * @param roundKeys 5 16-bit round keys
   * @return the resulting ciphertext
   */
  public BitSet SpnEncBlock(BitSet p, BitSet[] roundKeys) {
    p = Util.copyBitSet(p, 16);
    if (roundKeys.length != 5) {
      throw new IllegalArgumentException("There should be exactly 5 round keys");
    }
    
    for (int i = 0; i < 4; i++) {
      p = SpnEncRound(p, roundKeys[i], i != 3);
    }
    
    p.xor(roundKeys[4]);    
    return p;
  }
  
  /**
   * Decrypt a block c with the SPN cipher
   * @param c 16-bit ciphertext block
   * @param roundKeys 5 16-bit round keys
   * @return the resulting plaintext
   */
  public BitSet SpnDecBlock(BitSet c, BitSet[] roundKeys) {
    c = Util.copyBitSet(c, 16);
    if (roundKeys.length != 5) {
      throw new IllegalArgumentException("There should be exactly 5 round keys");
    }
    
    c.xor(roundKeys[4]);
    
    for (int i = 3; i >= 0; i--) {
      c = SpnDecRound(c, roundKeys[i], i != 3);
    }
    
    return c;    
  }
  
}
