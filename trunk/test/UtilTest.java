import java.util.BitSet;

import junit.framework.TestCase;


public class UtilTest extends TestCase {
  
  public void testIncrement() {
    BitSet set = new BitSet(4);
    set.set(0,3,false);
    for (int i = 0; i < 16; i++) {
      DesImplTest.printBitSet(set, 4, 4);
      Util.increment(set, 4);
    }

    DesImplTest.printBitSet(set, 4, 4);
  }
  
  public void testToInteger() {
    BitSet set = new BitSet(4);
    set.set(0,3,false);
    for (int i = 0; i < 16; i++) {
      System.out.print(Util.toInteger(set, 4) + " : ");

      DesImplTest.printBitSet(set, 4, 4);

      Util.increment(set, 4);
    }
  }
  
  public void testToBitSet() {
    int totalBits = 8;
    int value = 4;
    BitSet s = Util.toBitSet(value, totalBits);
    DesImplTest.printBitSet(s, 8, 8);
    
    value = 1;
    s = Util.toBitSet(value, totalBits);
    DesImplTest.printBitSet(s, 8, 8);
    
    value = 255;
    s = Util.toBitSet(value, totalBits);
    DesImplTest.printBitSet(s, 8, 8);
   
  }

}
