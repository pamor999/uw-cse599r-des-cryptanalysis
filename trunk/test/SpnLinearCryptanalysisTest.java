import java.util.BitSet;
import java.util.List;

import junit.framework.TestCase;


public class SpnLinearCryptanalysisTest extends TestCase {
  public void testGenerateRandomPairs() {
    // generate 100 pairs
    helpTestGenerateRandomPairs(100);
    // generate 1000 pairs
    helpTestGenerateRandomPairs(1000);
    // generate 10000 pairs
    helpTestGenerateRandomPairs(10000);
    
  }
  
  
  public void helpTestGenerateRandomPairs(int pairs) {
    BitSet[] roundKeys = new BitSet[] {
        Util.toBitSet(0x1234, 16),
        Util.toBitSet(0xDEAD, 16),
        Util.toBitSet(0x5678, 16),
        Util.toBitSet(0xACE1, 16),
        Util.toBitSet(0xFEED, 16),
    };
    
    SpnLinearCryptanalysis slc = new SpnLinearCryptanalysis();
    
    long time = System.currentTimeMillis();
    List<BitSet[]> val = slc.generateRandomPairs(pairs, roundKeys);
    time = System.currentTimeMillis() - time;
    System.out.println("Time to generate " + pairs + " pairs: " + time + " ms");
    
    // verify pairs
    System.out.print("Verifying pairs...");
    SpnImpl spn = new SpnImpl();
    for (BitSet[] set : val) {
      assertEquals(2, set.length);
      assertNotNull(set[0]);
      assertNotNull(set[1]);
      BitSet dec = spn.SpnDecBlock(set[1], roundKeys);
      assertTrue(Util.equalsBitSet(set[0], dec, 16));
    }
    System.out.println("done");
  }

}
