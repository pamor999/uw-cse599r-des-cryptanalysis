import java.util.BitSet;


public class DifferentialCryptanalysis {
  
  // Prints the Differential Tables for all Sboxes
  /**
 * @param args
 */
public static void main(String[] args) {
    
    for (int sbox = 0 ; sbox < 8; sbox++) {
      System.out.println("SBOX: " + (sbox + 1));
      
      
      BitSet alpha = new BitSet(6);
      alpha.set(0, 5, false);
      BitSet beta = new BitSet(4);
      beta.set(0, 3, false);
      
      for (int i = 0; i < 16; i++) {
        System.out.print("\t" + i);
      }
      System.out.println();
      
      for (int i = 0; i < 64; i++) {
        System.out.print(i + ":\t");
        for (int j = 0; j < 16; j++) {
          int ns = BihamShamirNS(sbox, alpha, beta);
          
          Util.increment(beta, 4);          
          System.out.print(ns + "\t");          
        }        
        Util.increment(alpha, 6);        
        System.out.println();        
      }
      System.out.println();
      System.out.println();
      
    }    
        
  }
  
  
  /**
   * Defines the NS function in lines of Biham Shamir "Differential Cyptanalysis of DES like Cryptosystems"
   * @param sbox identifies the S-Box (1 to 8)
   * @param alpha represents a value between 0 and 63 selecting bits of the input difference
   * @param beta represents a value between 0 and 15 selecting bits of the output difference
   * @return The number of times the pair 'alpha -> beta' occurs (0 to 64)
   */
  public static int BihamShamirNS(int sbox, BitSet alpha, BitSet beta) {
    int count = 0;
    BitSet input = new BitSet(6);
    input.set(0, 5, false);
    
    for (int i = 0; i < 64; i++) {
      BitSet current = (BitSet)input.clone();
      DesImpl des = new DesImpl();
      
      //compute Y
      BitSet Y = des.SBoxSingle(sbox, current);
        
    	
      // compute Y*
      current = (BitSet)input.clone();
      current.xor(alpha);
      BitSet Ystar = des.SBoxSingle(sbox, current);
      
      // equality
      Y.xor(Ystar);
      if (Y.equals(beta)) {
        count++;
      }

      // increment the input for the next round
      Util.increment(input, 6);
    }
    
    return count;
  }

}
