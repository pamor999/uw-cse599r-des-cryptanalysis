import java.util.BitSet;

import junit.framework.TestCase;


public class DesImplTest extends TestCase {
  public void testE() {
    DesImpl des = new DesImpl();
    
//    byte[] R = new byte[32];
//    for (int i = 0; i < 32; i++) {
//      R[i] = (byte)(i + 1);
//    }
    
    BitSet R = new BitSet(32);
    for (int i = 0; i < 8; i ++) {
      R.set(i, true);
    }
    
    printBitSet(des.E(R), 12, 48);
  }
  
  public void testFeistelRound() {
    BitSet L = new BitSet(32);
    BitSet R = new BitSet(32);
    BitSet K = new BitSet(32);
    
    for (int i = 0; i < 32; i++) {
      boolean value = Math.random() < 0.5;
      L.set(i, value);
      
      value = Math.random() < 0.5;
      R.set(i, value);

      value = Math.random() < 0.5;
      K.set(i, value);
    }
    
    DesImpl des = new DesImpl();
    
    System.out.print("L: ");
    printBitSet(L, 32, 32);
    System.out.print("R: ");
    printBitSet(R, 32, 32);
    System.out.print("K: ");
    printBitSet(K, 32, 32);
    
    System.out.println("Feistel...");
    
    BitSet[] result = des.FeistelRound(L, R, K);
    
    System.out.print("L': ");
    printBitSet(result[0], 32, 32);
    System.out.print("R': ");
    printBitSet(result[1], 32, 32);
    
    System.out.println("Inverse Feistel with same key...");
    
    result = des.FeistelRound(result[1], result[0], K);
    
    System.out.print("L'': ");
    printBitSet(result[1], 32, 32);
    System.out.print("R'': ");
    printBitSet(result[0], 32, 32);
    
    
  }
  
  public static void printBitSet(BitSet set, int lineLength, int setLength) {
    int ptr = 0;
    while(ptr < setLength) {
      System.out.print(set.get(ptr) ? "1" : "0");
      if (++ptr % lineLength == 0) {
        System.out.println();
      }
    }
  }
  
  
  public static void printBitArray(byte[] arr, int lineLength) {
    int ptr = 0;
    while(ptr < arr.length) {
      int value = (arr[ptr] < 0) ? 256 - arr[ptr] : arr[ptr];
      String formatted = (value < 10) ? "  " + value : 
        (value < 100) ? " " + value : "" + value;
      
      System.out.print(formatted + "  ");
      if (++ptr % lineLength == 0) {
        System.out.println();
      }
    }
  }
}
