import java.util.BitSet;

import junit.framework.TestCase;


public class SpnImplTest extends TestCase {
  
  public void testRoundTrip() {
    System.out.println("-----");
    BitSet p = Util.toBitSet(0xBEEF, 16);
    BitSet[] keys = new BitSet[] {
        Util.toBitSet(0x1234, 16),
        Util.toBitSet(0xDEAD, 16),
        Util.toBitSet(0x5678, 16),
        Util.toBitSet(0xACE1, 16),
        Util.toBitSet(0xFEED, 16),
    };
    
    SpnImpl spn = new SpnImpl();
    
    
    DesImplTest.printBitSet(p, 16, 16);
    BitSet c = spn.SpnEncBlock(p, keys);
    DesImplTest.printBitSet(c, 16, 16);
    BitSet pnew = spn.SpnDecBlock(c, keys);
    DesImplTest.printBitSet(pnew, 16, 16);
    
  }
  
  public void testSboxFunc() {
    System.out.println("-----");
    SpnImpl spn = new SpnImpl();
    
    BitSet s = Util.toBitSet(0xE, 4);
    DesImplTest.printBitSet(s, 4, 4);
    BitSet sres = spn.sBoxFunc(s, false);
    DesImplTest.printBitSet(sres, 4, 4);
    BitSet sres2 = spn.sBoxFunc(sres, true);
    DesImplTest.printBitSet(sres2, 4, 4);
    
  }
  
  public void testSboxes() {
    System.out.println("-----");
    SpnImpl spn = new SpnImpl();
    
    BitSet s = Util.toBitSet(0xBEEF, 16);
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.sBoxes(s, false);
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.sBoxes(s, true);
    DesImplTest.printBitSet(s, 16, 16);
  }
  
  public void testPermuteInvolution() {
    System.out.println("-----");
    SpnImpl spn = new SpnImpl();
    
    BitSet s = Util.toBitSet(0xBEEF, 16);
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.Permute(s);
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.Permute(s);
    DesImplTest.printBitSet(s, 16, 16);
  }
  
  public void testRound() {
    System.out.println("-----");
    SpnImpl spn = new SpnImpl();
    
    
    BitSet s = Util.toBitSet(0xBEEF, 16);
    BitSet k = Util.toBitSet(0x1234, 16);
    
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.SpnEncRound(s, k, true);
    DesImplTest.printBitSet(s, 16, 16);
    s = spn.SpnDecRound(s, k, true);
    DesImplTest.printBitSet(s, 16, 16);
  }

}
