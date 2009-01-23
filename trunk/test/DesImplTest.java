import java.util.BitSet;

import junit.framework.TestCase;


public class DesImplTest extends TestCase {
  public void testDES() {
	  int numRounds = 16;
	  System.out.println("Testing " + numRounds + " round DES ...");
	  
	  BitSet P = new BitSet(64);
	  BitSet K = new BitSet(64);
	  
	  // initialize random P and K
	  for (int i = 0; i < 64; i++) {
	      boolean value = Math.random() < 0.5;
	      P.set(i, value);
	      
	      value = Math.random() < 0.5;
	      K.set(i, value);
	  }
	  
	  DesImpl des = new DesImpl();
	  
	  // test DES encoding
	  System.out.println("DES Encoding ...");
	  BitSet C = des.DesEncBlock(P, K, numRounds);
	  
	  System.out.print("P:  ");
	  printBitSet(P,64,64);
	  System.out.print("K:  ");
	  printBitSet(K,64,64);
	  System.out.print("C:  ");
	  printBitSet(C,64,64);
	  
	  // test DES decoding
	  System.out.println("DES Decoding ...");
	  BitSet decodedP = des.DesDecBlock(C, K, numRounds);
	  
	  System.out.print("P': ");
	  printBitSet(decodedP,64,64);
	  
	  // test if P == decodedP
	  assertTrue(Util.equalsBitSet(P, decodedP, 64));
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
  
}
