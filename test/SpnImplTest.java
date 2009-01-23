import java.util.BitSet;

import junit.framework.TestCase;


public class SpnImplTest extends TestCase {
  
  public void testSPN() {
    System.out.println("Testing SPN ...");
    BitSet p = Util.toBitSet(0xBEEF, 16);
    BitSet[] keys = new BitSet[] {
        Util.toBitSet(0x1234, 16),
        Util.toBitSet(0xDEAD, 16),
        Util.toBitSet(0x5678, 16),
        Util.toBitSet(0xACE1, 16),
        Util.toBitSet(0xFEED, 16),
    };
    
    SpnImpl spn = new SpnImpl();
    
    System.out.println("SPN Encoding ...");
	System.out.print("P:  ");
	printBitSet(p, 16, 16);
    BitSet c = spn.SpnEncBlock(p, keys);
    System.out.print("C:  ");
	printBitSet(c, 16, 16);
    
	System.out.println("SPN Decoding ...");
	BitSet pnew = spn.SpnDecBlock(c, keys);
    System.out.print("P': ");
	printBitSet(pnew, 16, 16);
    
	// test if p == pnew
	assertTrue(Util.equalsBitSet(p, pnew, 16));
    
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
