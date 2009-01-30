import java.util.BitSet;

/**
 * Implementation of variable-round DES
 * 
 * @author Slava Chernyak and Sourav Sen Gupta
 * 
 */
public class DesImpl {
	/** Flag determines weather the initial permutation is applied */
	public static final boolean DES_INITIAL_PERMUTATION = false;

	/** S-Boxes for DES */
	public static final int[][][] S = new int[][][] {
			{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
					{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
					{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
					{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },

			{ { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
					{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
					{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
					{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },

			{ { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
					{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
					{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
					{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },

			{ { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
					{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
					{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
					{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },

			{ { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
					{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
					{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
					{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },

			{ { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
					{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
					{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
					{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },

			{ { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
					{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
					{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
					{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },

			{ { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
					{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
					{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
					{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };

	/** permutation P for the DES rounds */
	public static final int[] C_PERM = new int[] { 16, 7, 20, 21, 29, 12, 28, 17,
			1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6,
			22, 11, 4, 25 };

	/** Inverse of the above permutation - for cryptanalysis */
	public static final int[] C_PERM_INV = new int[] { 
			9,// 1
			17,// 2
			23,// 3
			31,// 4
			13,// 5
			28,// 6
			2,// 7
			18,// 8
			24,// 9
			16,// 10
			30,// 11
			6,// 12
			26,// 13
			20,// 14
			10,// 15
			1,// 16
			8,// 17
			14,// 18
			25,// 19
			3,// 20
			4,// 21
			29,// 22
			11,// 23
			19,// 24
			32,// 25
			12,// 26
			22,// 27
			7,// 28
			5,// 29
			27,// 30
			15,// 31
			21,// 32
	};

	/** PC-1 box for DES Key Schedule */
	public static final int[] PC1 = new int[] { 57, 49, 41, 33, 25, 17, 9, 1, 58,
			50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
			37, 29, 21, 13, 5, 28, 20, 12, 4 };

	/** PC-2 box for DES Key Schedule */
	public static final int[] PC2 = new int[] { 14, 17, 11, 24, 1, 5, 3, 28, 15,
			6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37,
			47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36,
			29, 32 };

	/** Number of left shifts in the key for each round of DES */
	public static final int[] LS = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2,
			2, 2, 2, 2, 1 };

	/** Initial permutation box IP */
	public static final int[] IP = new int[] { 58, 50, 42, 34, 26, 18, 10, 2, 60,
			52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40,
			32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
			3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

	/** Inverse initial permutation box IP_inv */
	public static final int[] IP_inv = new int[] { 40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45,
			13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
			59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

	/**
	 * Compute initial permutation IP
	 * @param P 64-bit block
	 * @return permuted 64-bit block
	 */
	public BitSet InitPerm(BitSet P) {
		P = Util.copyBitSet(P, 64);
		BitSet P_perm = new BitSet(64);
		for (int i = 0; i < 64; i++) {
			P_perm.set(i, P.get(IP[i] - 1));
		}
		return P_perm;
	}

	/**
	 * Compute inverse initial permutation IP^-1
	 * @param C 64-bit block
	 * @return un-permuted 64-bit block
	 */
	public BitSet InvInitPerm(BitSet C) {
		C = Util.copyBitSet(C, 64);
		BitSet C_final = new BitSet(64);
		for (int i = 0; i < 64; i++) {
			C_final.set(i, C.get(IP_inv[i] - 1));
		}
		return C_final;
	}

	/**
	 * DES Expansion permutation for feistel function
	 * @param R 32-Bit block
	 * @return Expanded 48-bit block
	 */
	public BitSet E(BitSet R) {
		int eptr = 0;
		BitSet e = new BitSet(48);

		for (int group = 0; group < 8; group++) {
			for (int i = 0; i < 6; i++) {
				e.set(eptr++, R.get((31 + (group * 4) + i) % 32));
			}
		}
		return e;
	}

	/** 
	 * S Box function S_sbox[input] for DES
	 * @param sbox S-Box to use (0 to 7)
	 * @param input 6-bit S-Box input
	 * @return 4-bit S-Box output
	 */
	public BitSet SBoxSingle(int sbox, BitSet input) {
		int row = (input.get(0) ? 2 : 0) + (input.get(5) ? 1 : 0);
		int col = (input.get(1) ? 8 : 0) + (input.get(2) ? 4 : 0)
				+ (input.get(3) ? 2 : 0) + (input.get(4) ? 1 : 0);
		int sval = S[sbox][row][col];

		BitSet result = new BitSet(4);
		for (int j = 0; j < 4; j++) {
			result.set(j, (((sval >> (3 - j)) & 1) != 0));
		}
		return result;
	}

	/** 
	 * Apply all S-Boxes in feistel function.
	 * @param ER Expanded 48-bit block
	 * @return 32-bit concatenated S-Box result
	 */
	public BitSet SBox(BitSet ER) {
		// compute results of s-boxes
		BitSet C = new BitSet(32);
		for (int i = 0; i < 8; i++) {
			BitSet B_i = ER.get(6 * i, 6 * (i + 1));
			BitSet S_i = SBoxSingle(i, B_i);
			for (int j = 0; j < 4; j++) {
				C.set(4 * i + j, S_i.get(j));
			}
		}
		// for (int i = 0; i < 8; i++) {
		//      
		// int row = (ER.get(0 + (6 * i)) ? 2 : 0) + (ER.get(5 + (6 * i)) ? 1 : 0);
		// int col = (ER.get(1 + (6 * i)) ? 8 : 0) + (ER.get(2 + (6 * i)) ? 4 : 0)
		// + (ER.get(3 + (6 * 1)) ? 2 : 0) + (ER.get(4 + (6 * i)) ? 1 : 0);
		// int sval = S[i][row][col];
		// for (int j = 0; j < 4; j++) {
		// C.set(i * 4 + j, (((sval >> (3 - j)) & 1) != 0 ));
		// }
		// }
		return C;
	}

	/**
	 * Apply the C-permutation 
	 * @param C 32-Bit block
	 * @return Permuted 32-Bit block
	 */
	public BitSet PermuteC(BitSet C) {
		// permute sbox results
		BitSet P = new BitSet(32);
		for (int i = 0; i < 32; i++) {
			P.set(i, C.get(C_PERM[i] - 1));
		}
		return P;
	}

	/**
	 * Inverse of the C-permutation above
	 * @param C 32-Bit block
	 * @return un-permuted 32-Bit block
	 */
	public BitSet PermuteCInv(BitSet C) {
		// un permute
		BitSet P = new BitSet(32);
		for (int i = 0; i < 32; i++) {
			P.set(i, C.get(C_PERM_INV[i] - 1));
		}
		return P;
	}

	/**
	 * Produces the round key from the given DES key
	 * for the specified round
	 * @param K 56 Bit key
	 * @param round round number (1 to 16)
	 * @return 48 Bit round key
	 */
	public BitSet KeySchedule(BitSet K, int round) {
		// the 64 bit key provided
		BitSet K64 = Util.copyBitSet(K, 64);

		// produce the 56 bit key using PC-1
		BitSet K56 = new BitSet(56);
		for (int i = 0; i < 56; i++) {
			K56.set(i, K64.get(PC1[i] - 1));
		}
		BitSet C = K56.get(0, 28);
		BitSet D = K56.get(28, 56);

		// perform the left shifts to C and D blocks
		int shift = 0;
		for (int i = 0; i < round; i++) {
			shift += LS[i];
		}

		BitSet Cround = new BitSet(28);
		BitSet Dround = new BitSet(28);
		for (int i = 0; i < 28; i++) {
			Cround.set(i, C.get((i + shift) % 28));
			Dround.set(i, D.get((i + shift) % 28));
		}
		BitSet K56round = Util.concatenate(Cround, 28, Dround, 28);

		// choose the 48 bit round key using PC-2
		BitSet K48round = new BitSet(48);
		for (int i = 0; i < 48; i++) {
			K48round.set(i, K56round.get(PC2[i] - 1));
		}
		return K48round;
	}

	/**
	 * Performs the Feistel function on the given 
	 * bit set and key
	 * @param R
	 *          32 Bit Set
	 * @param K
	 *          48 Bit Key
	 * @return
	 */
	public BitSet Feistel(BitSet R, BitSet K) {
		// expand
		BitSet ER = E(R);

		// XOR in the key
		ER.xor(K);

		// Compute S-box values
		BitSet C = SBox(ER);

		// Permute S-box results
		return PermuteC(C);
	}

	/**
	 * Performs one round of DES (Feistel cipher) on the given
	 * Left, Right, and round Key bit sets
	 * @param L 32 Bit left set
	 * @param R 32 Bit right set
	 * @param K 48 Bit round key
	 * @return Array containing 2 entries. First entry is the 
	 * resulting left 32 Bit set, second entry is the resulting
	 * right 32 Bit set.
	 */
	public BitSet[] FeistelRound(BitSet L, BitSet R, BitSet K) {
		// L' = L + F(R,K)
		L.xor(Feistel(R, K));

		// R' = R

		// swap(L',R')
		return new BitSet[] { R, L };
	}

	/**
	 * Encode given block using DES using specified number of rounds
	 * @param P 64 Bit plaintext
	 * @param K 56 Bit key
	 * @param numRounds number of rounds to use (1 to 16)
	 * @return 64 Bit ciphertext
	 */
	public BitSet DesEncBlock(BitSet P, BitSet K, int numRounds) {
		P = Util.copyBitSet(P, 64);
		K = Util.copyBitSet(K, 64);
		if (numRounds > 16) {
			throw new IllegalArgumentException(
					"The code does not support more than 16 rounds of DES");
		}

		// initial permutation IP
		BitSet P_perm = DES_INITIAL_PERMUTATION ? InitPerm(P) : P;

		// the Feistel rounds
		BitSet L = P_perm.get(0, 32);
		BitSet R = P_perm.get(32, 64);

		for (int round = 1; round <= numRounds; round++) {
			BitSet Kround = KeySchedule(K, round);
			BitSet[] result = FeistelRound(L, R, Kround);

			L = result[0];
			R = result[1];
		}

		// codeword after the Feistel rounds (udoing the last swap)
		BitSet C = Util.concatenate(R, 32, L, 32);

		// inverse IP
		BitSet C_final = DES_INITIAL_PERMUTATION ? InvInitPerm(C) : C;

		return C_final;
	}

	/**
	 * Decode given block using DES with specified number of rounds
	 * @param C 64 Bit ciphertext
	 * @param K 56 Bit key
	 * @param numRounds number of rounds to use (1 to 16)
	 * @return 64 Bit plaintext
	 */
	public BitSet DesDecBlock(BitSet C, BitSet K, int numRounds) {
		C = Util.copyBitSet(C, 64);
		K = Util.copyBitSet(K, 64);
		if (numRounds > 16) {
			throw new IllegalArgumentException(
					"The code does not support more than 16 rounds of DES");
		}

		// initial permutation IP
		BitSet C_perm = DES_INITIAL_PERMUTATION ? InitPerm(C) : C;

		// the inverse Feistel rounds
		BitSet L = C_perm.get(0, 32);
		BitSet R = C_perm.get(32, 64);

		for (int round = numRounds; round > 0; round--) {
			BitSet Kround = KeySchedule(K, round);
			BitSet[] result = FeistelRound(L, R, Kround);
			// undo the last swap
			L = result[0];
			R = result[1];
		}

		// decoded plaintext after the inverse Feistel rounds (udoing last swap)
		BitSet P = Util.concatenate(R, 32, L, 32);

		// inverse IP
		BitSet P_final = DES_INITIAL_PERMUTATION ? InvInitPerm(P) : P;

		return P_final;
	}
}
