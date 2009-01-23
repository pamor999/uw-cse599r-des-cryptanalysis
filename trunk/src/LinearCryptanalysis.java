import java.util.BitSet;


public class LinearCryptanalysis {
  
  // Prints the Linear Approximation for all Sboxes
  /**
 * @param args
 */
public static void main(String[] args) {
    int max = 0;
    int maxAlpha = -1;
    int maxBeta = -1;
    
    for (int sbox = 0 ; sbox < 8; sbox++) {
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
      
      System.out.println("Max |NS| for SBox " +  (sbox + 1) + " is " + max + " with alpha " + 
    	        maxAlpha + " and beta " + maxBeta);
      System.out.println();
      System.out.println();
      
    }    
        
  }
  
  
  /**
   * Defines the NS function as in Matsui "Linear Cryptanalysis Method for DES cipher"
   * @param sbox identifies the S-Box (1 to 8)
   * @param alpha repesents a value between 0 and 63 selecting bits of the input to be
   *  xor-ed 
   * @param beta represents a value between 0 and 15 selecting bits of the output to be
   *  xor-ed 
   * @return The number of times the values of the xored expressoins coincide (0 to 64)
   */
  public static int MatsuiNS(int sbox, BitSet alpha, BitSet beta) {
    int count = 0;
    BitSet input = new BitSet(6);
    input.set(0, 5, false);
    
    for (int i = 0; i < 64; i++) {
      // compute the LHS of NS
      BitSet current = (BitSet)input.clone();
      current.and(alpha);
      boolean leftResult = Util.DirectSum(current, 6);
      
      // compute the RHS of NS
      current = (BitSet)input.clone();
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

}
