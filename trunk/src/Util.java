import java.util.BitSet;

/**
 * Static utilities for BitSet class
 * 
 * @author Slava Chernyak
 * 
 */
public final class Util {
  private Util() {
  }

  /**
   * Increment the numeric value represented by this bit set
   * 
   * @param set
   *          to increment
   * @param totalBits
   *          number of bits in the bit set
   * @return bit set with incremented value
   */
  public static BitSet increment(BitSet set, int totalBits) {
    boolean carry = true;
    int place = totalBits - 1;
    while (carry && place >= 0) {
      carry = set.get(place);
      set.set(place, !set.get(place));
      place--;
    }
    return set;
  }

  /**
   * Compute the direct sum (XOR) of all the bits in the set
   * 
   * @param set
   *          to compute direct sum on
   * @param totalBits
   *          number of bits in the bit set
   * @return value of direct sum
   */
  public static boolean DirectSum(BitSet set, int totalBits) {
    boolean acc = false;
    for (int i = 0; i < totalBits; i++) {
      acc ^= set.get(i);
    }
    return acc;
  }

  /**
   * Convert bit set to integer value (low numbered bits highiest order)
   * 
   * @param set
   *          to compute integer value of
   * @param totalBits
   *          number of bits in the bit set
   * @return integer value of bits in the set
   */
  public static int toInteger(BitSet set, int totalBits) {
    int acc = 0;
    for (int i = 0; i < totalBits; i++) {
      acc += ((set.get(totalBits - i - 1)) ? 1 : 0) << i;
    }
    return acc;
  }

  /**
   * Convert integer to bit set with desired value (low numbered bits are
   * highest order)
   * 
   * @param value
   *          to convert to bit set
   * @param totalBits
   *          number of bits in the resulting bit set
   * @return Bit set with desired number of bits and integer value
   */
  public static BitSet toBitSet(int value, int totalBits) {
    int idx = totalBits - 1;
    BitSet result = new BitSet();
    while (value > 0) {
      result.set(idx--, value % 2 == 1);
      value /= 2;
    }
    return result;
  }

  /**
   * Tests weather two bit sets are equal bitwise
   * 
   * @param a
   * @param b
   * @param totalBits
   * @return true if they are equal, false otherwise
   */
  public static boolean equalsBitSet(BitSet a, BitSet b, int totalBits) {
    for (int i = 0; i < totalBits; i++) {
      boolean ca = a.get(i);
      boolean cb = b.get(i);
      if (ca != cb)
        return false;
    }
    return true;
  }

  /**
   * Create a deep copy of specified bit set
   * 
   * @param set
   * @param totalBits
   * @return
   */
  public static BitSet copyBitSet(BitSet set, int totalBits) {
    BitSet newset = new BitSet();
    for (int i = 0; i < totalBits; i++) {
      newset.set(i, set.get(i));
    }
    return newset;

  }

  /**
   * Concatenate bit sets with specified numbers of bits to bit set with number
   * of bits equal to the sum of the two
   * 
   * @param a
   * @param totalBitsA
   * @param b
   * @param totalBitsB
   * @return
   */
  public static BitSet concatenate(BitSet a, int totalBitsA, BitSet b,
      int totalBitsB) {
    for (int i = 0; i < totalBitsB; i++) {
      a.set(totalBitsA + i, b.get(i));
    }
    return a;
  }

  /**
   * Concatenate an array of bit sets of equal length
   * 
   * @param sets
   *          Array of sets to concatenate
   * @param totalBitsEach
   *          number of bits in each bit set to concatenate
   * @return A single bit set with concatenated bits
   */
  public static BitSet concatenate(BitSet[] sets, int totalBitsEach) {
    BitSet result = new BitSet(sets.length * totalBitsEach);
    for (int i = 0; i < sets.length; i++) {
      for (int j = 0; j < totalBitsEach; j++) {
        result.set((i * totalBitsEach) + j, sets[i].get(j));
      }
    }
    return result;
  }
  
  /**
   * Print a bit set to the screen
   * @param set
   * @param totalBits
   */
  public static void printBitSet(BitSet set, int totalBits) {
    int ptr = 0;
    while (ptr < totalBits) {
      int val = Util.toInteger(set.get(ptr, ptr + 4), 4);
      System.out.print(Integer.toHexString(val).toUpperCase());
      //System.out.print(set.get(ptr) ? "1" : "0");
//      if (++ptr % lineLength == 0) {
//        System.out.println();
//      }
      ptr += 4;
    }
    System.out.println();
  }
}
