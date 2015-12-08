package final_project;

import java.math.BigInteger;
import java.util.Random;
import java.util.Arrays;

/**
 * @author Nikita Nikita 
 * N12538559
 * nn899
 * 3205 : Applied Cryptography and Network Security
 * Spring 2015
 * Final Project
 */
public class RSA {

	static int arri[], q[], r[], r1[], r2[], s[], t[]; // used in
														// extendedEuclideanAlgo()
	static int arrYsq[], arrYmul[], expIndex;
	static String arrXi[];
	int primeP, primeQ; // prime numbers
	int e, d; // public-key, private-key
	int n, hashR;
	String rCertStr, entityName;
	static int index;
	static boolean traceFlag, traceNotPrime, tracePrime; // flags for traces

	public RSA(String name) {
		entityName = name;
		index = 0;
		arri = new int[50];
		q = new int[50];
		r = new int[50];
		r1 = new int[50];
		r2 = new int[50];
		s = new int[50];
		t = new int[50];
		arrXi = new String[50];
		arrYsq = new int[50];
		arrYmul = new int[50];
		expIndex = 0;
		traceFlag = false;
		traceNotPrime = false;
		tracePrime = false;
	}

	/*
	 * Generates a random number for user Gets 5 numbers and extracts their
	 * Least Significant Bit for generation
	 */
	public int generateRandomNumber(Random generator) {

		int n1, n2, n3, n4, n5;

		// generate 5 uniformly distributed int value between 1
		// and (2^31)-1.
		n1 = generator.nextInt(Integer.MAX_VALUE) + 1;
		n2 = generator.nextInt(Integer.MAX_VALUE) + 1;
		n3 = generator.nextInt(Integer.MAX_VALUE) + 1;
		n4 = generator.nextInt(Integer.MAX_VALUE) + 1;
		n5 = generator.nextInt(Integer.MAX_VALUE) + 1;

		String x1 = Integer.toString(n1, 2);
		String x2 = Integer.toString(n2, 2);
		String x3 = Integer.toString(n3, 2);
		String x4 = Integer.toString(n4, 2);
		String x5 = Integer.toString(n5, 2);

		String y1 = x1.substring(x1.length() - 1);
		String y2 = x2.substring(x2.length() - 1);
		String y3 = x3.substring(x3.length() - 1);
		String y4 = x4.substring(x4.length() - 1);
		String y5 = x5.substring(x5.length() - 1);
		String y = "1" + y1 + y2 + y3 + y4 + y5 + "1";
		// Get the integer value for string y
		int n = Integer.parseInt(y, 2);

		if (traceFlag) {
			System.out
					.println("----------------------------------------------------------------");
			System.out.println("Line = 97");
			System.out.println("number 1 = " + n1 + ", in bits = " + x1
					+ ", bit1 = " + y1);
			System.out.println("number 2 = " + n2 + ", in bits = " + x2
					+ ", bit2 = " + y2);
			System.out.println("number 3 = " + n3 + ", in bits = " + x3
					+ ", bit3 = " + y3);
			System.out.println("number 4 = " + n4 + ", in bits = " + x4
					+ ", bit4 = " + y4);
			System.out.println("number 5 = " + n5 + ", in bits = " + x5
					+ ", bit5 = " + y5);
			System.out.println("n = " + n + ", in bits = " + y);
			traceFlag = false;

		}

		return n;
	}

	/*
	 * Uses Miller-Rabin algorithm (as taught in class notes) to check for
	 * primality. Generates 20 random values of 'a' for testing
	 */
	public Boolean checkPrime(int n, Random randomVar) {

		int a = 0;
		int cpArri[] = new int[40]; // i values
		int cpArrz[] = new int[40]; // z values
		int cpArrYsq[] = new int[40]; // y*y mod n values
		int cpArrYmul[] = new int[40]; // y*a mod n values
		char cpArrXi[] = new char[40]; // xi
		int li = 0;

		for (int count = 1; count <= 20; count++) {
			li = 0;
			a = randomVar.nextInt(n);
			// ignore zero values
			while (a == 0)
				a = randomVar.nextInt(n);

			// to get length of n
			String s = Integer.toString(n - 1, 2);

			int j = 0, y = 1;
			for (int i = s.length() - 1; i >= 0; i--) {
				int z = y;
				y = (y * y) % n;

				cpArri[li] = i;
				cpArrz[li] = z;

				if (y == 1 && z != 1 && z != (n - 1)) {
					// display one trace for not a prime number
					if (!traceNotPrime) {
						System.out
								.println("-----------------Not Prime--------------------------------------");
						System.out.println("Line = 119");
						System.out.println("n = " + n + " , a = " + a);
						System.out.println(" i |   xi   z     y     y");
						System.out.println("--------------------------");

						for (int k = 0; k < li; k++) {
							String si = Integer.toString(cpArri[k]); // i
							String sz = Integer.toString(cpArrz[k]); // z
							String ysq = Integer.toString(cpArrYsq[k]); // y
							String ymul = Integer.toString(cpArrYmul[k]); // y
							System.out.format("%2s | %4c %4s %4s %4s\n", si,
									cpArrXi[k], sz, ysq, ymul);

						}
						System.out.println("\n");
						traceNotPrime = true;
					}
					return false;
				}
				cpArrYsq[li] = y;
				cpArrXi[li] = s.charAt(j);
				if (s.charAt(j) == '1')
					y = (y * a) % n;
				cpArrYmul[li] = y;
				j++;
				li++;
			}

			if (y != 1) {
				// display one trace for not a prime number
				if (!traceNotPrime) {
					System.out
							.println("----------------------not prime-------------------------------------");
					System.out.println("Line = 119");
					System.out.println("n = " + n + " , a = " + a);
					System.out.println(" i |   xi   z     y     y");
					System.out.println("--------------------------");

					for (int k = 0; k < li; k++) {
						String si = Integer.toString(cpArri[k]);
						String sz = Integer.toString(cpArrz[k]);
						String sy1 = Integer.toString(cpArrYsq[k]);
						String sy = Integer.toString(cpArrYmul[k]);
						System.out.format("%2s | %4c %4s %4s %4s\n", si,
								cpArrXi[k], sz, sy1, sy);
					}
					System.out.println("\n");
					traceNotPrime = true;
				}
				return false;
			}
		}

		// display one trace for a prime number
		if (!tracePrime) {
			System.out
					.println("------------------perhaps prime--------------------------------------");
			System.out.println("Line = 123");
			System.out.println("n = " + n + " , a = " + a);
			System.out.println(" i |   xi   z     y     y");
			System.out.println("--------------------------");

			for (int k = 0; k < li; k++) {
				String si = Integer.toString(cpArri[k]);
				String sz = Integer.toString(cpArrz[k]);
				String sy1 = Integer.toString(cpArrYsq[k]);
				String sy = Integer.toString(cpArrYmul[k]);
				System.out.format("%2s | %4c %4s %4s %4s\n", si, cpArrXi[k],
						sz, sy1, sy);
			}
			System.out.println("\n");
			tracePrime = true;
		}

		return true;

	}

	/*
	 * Generates random numbers p and q for the RSA system
	 */
	public void generatePrimes(Random generator) {
		// get 2 random numbers
		primeP = generateRandomNumber(generator);
		primeQ = generateRandomNumber(generator);

		// check whether num1 and num2 are prime
		Boolean isPprime = checkPrime(primeP, generator);
		Boolean isQprime = checkPrime(primeQ, generator);

		// if we immediately find the prime numbers we need,
		// we pick any number we know not to be prime (composite number)
		// and perform the test on it.
		if (isPprime && isQprime)
			checkPrime(6, generator);

		if (!isPprime) {
			while (true) {
				primeP = generateRandomNumber(generator);
				isPprime = checkPrime(primeP, generator);
				if (isPprime)
					break;
			}
		}
		if (!isQprime) {
			while (true) {
				primeQ = generateRandomNumber(generator);
				isQprime = checkPrime(primeQ, generator);
				if (primeP == primeQ)
					continue;
				if (isQprime && primeP != primeQ)
					break;
			}
		}
		// p and q should be checked for equality
		if (primeP == primeQ) {
			while (true) {
				primeQ = generateRandomNumber(generator);
				isQprime = checkPrime(primeQ, generator);
				if (primeP == primeQ)
					continue;
				if (isQprime && primeP != primeQ)
					break;
			}
		}

		/*System.out.println("P = " + primeP);
		System.out.println("Q = " + primeQ);*/

	}

	/*
	 * runs ExtendedEuclidean algorithm on the numbers
	 */
	public int[] extendedEuclideanAlgo(int num1, int num2) {
		
		if (num2 == 0) {
			q[index] = -1;
			r[index] = num1;
			r1[index] = -1;
			r2[index] = -1;
			s[index] = 1;
			t[index] = 0;
			arri[index] = index + 1;
			index++;
			return new int[] { num1, 1, 0 };
		}
		int[] values = extendedEuclideanAlgo(num2, num1 % num2);

		int x = values[0];
		int n1 = values[2];
		int n2 = values[1] - (num1 / num2) * values[2];
		arri[index] = index + 1;
		q[index] = num1 / num2;
		r[index] = num1;
		r1[index] = num2;
		r2[index] = num1 % num2;
		s[index] = n1;
		t[index] = n2;
		index++;
		return new int[] { x, n1, n2 };
	}

	/*
	 * Generates public-private key pair for user
	 */
	public void generateKeysED(Random randomParam) {
		n = primeP * primeQ;

		int[] vals;
		int i = 3; // start from  3 Line 134
		Boolean flag = false;

		// calculate phi(n) = (p-1)(q-1)
		int phiN = (primeP - 1) * (primeQ - 1);

		// calculate key-pairs e & d
		if (entityName.contains("Alice")) {
			System.out
					.println("--------------Finding e,d----------------------------------");
			System.out.println("Line = 133");

		}

		while (true) {
			index = 0;
			vals = extendedEuclideanAlgo(phiN, i);
			if (entityName.contains("Alice")) {
				System.out.println("\n gcd(" + phiN + ", " + i + ") = "
						+ vals[0]);
				System.out
						.println("\n i | qi    r(i)     r(i+1)    r(i+2) \ts(i) \tt(i)");
				System.out
						.println("-----------------------------------------------------");
			}
			int k1 = index - 1;
			String qstr, r1str, r2str;
			for (int k = 0; k < index; k++) {
				if (q[k1] == -1)
					qstr = "-";
				else
					qstr = Integer.toString(q[k1]);
				if (r1[k1] == -1)
					r1str = "-";
				else
					r1str = Integer.toString(r1[k1]);
				if (r2[k1] == -1)
					r2str = "-";
				else
					r2str = Integer.toString(r2[k1]);
				if (entityName.contains("Alice"))
					System.out.format(
							"%2d | %5s %5d    %5s    %5s    %5d   %5d\n",
							arri[k], qstr, r[k1], r1str, r2str, s[k], t[k]);
				k1--;
			}

			if (vals[0] == 1)
				break;
			i++;
			if (i == phiN) {
				flag = true;
				break;
			}
		}
		

		if (entityName.contains("Alice"))
			System.out.println("\n" + vals[1] + "(" + phiN + ") + " + vals[2]
					+ "(" + i + ") = " + vals[0]);
		
		//We do not like negative numbers
		if (vals[2] < 0) {
			System.out.println("d = " + phiN + vals[2]);
			vals[2] = phiN - (Math.abs(vals[2]) % phiN);
		}

		//Set key-pair e and d
		e = i;
		d = vals[2];
		if (entityName.contains("Alice")) {
			System.out
					.println("-----------------------------------------------------------------");
			System.out.println("Line = 141");
			System.out.println("d = " + d);
		}

		if (entityName.contains("Alice")) {
			System.out
					.println("-----------------------Alice's key-pair---------------------------");
			System.out.println("Line = 145");
			System.out.println("p = " + primeP + ", p in bits = "
					+ Integer.toBinaryString(primeP));
			System.out.println("q = " + primeQ + ", q in bits = "
					+ Integer.toBinaryString(primeQ));
			System.out.println("n = " + n + ", n in bits = "
					+ Integer.toBinaryString(n));
			System.out.println("e = " + e + ", e in bits = "
					+ Integer.toBinaryString(e));
			System.out.println("d = " + d + ", d in bits = "
					+ Integer.toBinaryString(d));
		}
	}

	/*
	 * Calculates hash value using XOR operation on arr[]
	 */
	public int calculateHash(int toHashArr[]) {
		int hashResult = 0;

		for (int i = 0; i < toHashArr.length - 1; i++) {
			hashResult = toHashArr[i] ^ toHashArr[i + 1];
			toHashArr[i + 1] = hashResult;
		}
		return hashResult;
	}

	/*
	 * Performs fast exponentiation of a^x mod n
	 */
	public int fastExponentiation(int a, int x, int n, boolean flag) {

		if (x == -9999)
			x = d;

		int y = 1, j = 0, y1;
		String s = Integer.toBinaryString(x);
		int k = s.length() - 1;
		for (int i = k; i >= 0; i--) {
			y = (y * y) % n;
			y1 = y;
			if (s.charAt(j) == '1')
				y = (a * y) % n;

			if (flag) {
				arrXi[expIndex] = s.substring(j, j + 1);
				arrYsq[expIndex] = y1;
				arrYmul[expIndex] = y;
				expIndex++;
			}
			j++;
		}
		return y;
	}

	/*
	 * Generates a certificate for user given the owner name, public key and n,
	 * generates and signs the certificate
	 */
	public String[] generateCertificate(String ownerName, int e, int n) {

		// Get name of certificate owner in binary
		String binaryname = new BigInteger(ownerName.getBytes()).toString(2);

		// add leading zeros for name if binary name is smaller than 6-bytes
		// Line = 171
		if (binaryname.length() < 48) {
			int l = 48 - binaryname.length();
			for (int k = 0; k < l; k++)
				binaryname = "0" + binaryname;
		}
		// get the string representation of 'n' in binary.
		String nBinString = Integer.toBinaryString(n);

		// add leading zeros for n, if n < 32-bits
		// Line 173
		if (nBinString.length() < 32) {
			int nLen = 32 - nBinString.length();
			for (int k = 0; k < nLen; k++)
				nBinString = "0" + nBinString;
		}
		// get the string representation of 'e' in binary.
		String eBinString = Integer.toBinaryString(e);

		// Line 177
		// add leading zeros for e is smaller than 32 bits
		if (eBinString.length() < 32) {
			int eLen = 32 - eBinString.length();
			for (int k = 0; k < eLen; k++)
				eBinString = "0" + eBinString;
		}

		// Get r from name,n and e
		String r = binaryname + nBinString + eBinString;

		int nums[] = new int[14], j = 0;

		// calculate hash by converting r into individual bytes
		for (int i = 0; i < 14; i++) {
			nums[i] = Integer.parseInt(r.substring(j, j + 8), 2);
			j = j + 8;
		}

		hashR = calculateHash(nums);   
		String hashRBinStr = Integer.toBinaryString(hashR);

		// pad hash with zero values if it is less than 32 bits
		if (hashRBinStr.length() < 32) {
			int l = 32 - hashRBinStr.length();
			for (int k = 0; k < l; k++)
				hashRBinStr = "0" + hashRBinStr;
		}

		// Sign h(r) with Trent's private key : Line 179
		int sig = fastExponentiation(hashR, d, this.n, false);

		String sigBinString = Integer.toBinaryString(sig);

		// pad signature with zero values
		if (sigBinString.length() < 32) {
			int l = 32 - sigBinString.length();
			for (int k = 0; k < l; k++)
				sigBinString = "0" + sigBinString;
		}
		rCertStr = r;

		// Print r,h(r) and s as binary
		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 185");
		System.out.println("r = " + rCertStr);
		System.out.println("h(r) = " + hashRBinStr);
		System.out.println("s = " + sigBinString);

		// Print r,h(r) and s as binary
		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 187");
		System.out.println("h(r) = " + hashR);
		System.out.println("s = " + sig);

		// Place certificate as r and s together
		String cert[] = new String[2];
		cert[0] = r;
		cert[1] = sigBinString;
		return cert;
	}

	/*
	 * Generates random big u for Bob such that u < n
	 */
	public String generateUforBob() {
		String u = "";
		int r;
		int i;
		String nStr = Integer.toBinaryString(n); //get binary string for Bob's 'n'

		// add leading zeros for n
		if (nStr.length() < 32) {
			int l = 32 - nStr.length();
			for (int j = 0; j < l; j++)
				nStr = "0" + nStr;
		}
		// Get position of first bit = 1
		for (i = 0; i < 32; i++) {
			if (nStr.charAt(i) == '1')
				break;
		}
		int k = 31 - i;

		for (i = 0; i < 32 - k; i++) 
			u = "0" + u;
		u = u + "1";
		int len = 32 - u.length();
		Random generator = new Random();
		for (i = 0; i < len; i++) { 
			r = generator.nextInt(Integer.MAX_VALUE) + 1; //Line 201
			String rStr = Integer.toBinaryString(r);
			u = u + rStr.charAt(rStr.length() - 1);
		}

		/*
		 * Print k and u
		 */
		int unum = Integer.parseInt(u, 2);
		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 206");
		System.out.println("k = " + k);
		System.out.println("u = " + unum);

		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 208");
		System.out.println("u = " + u);
		return u;
	}

	/*
	 * Returns the public key of the user
	 */
	public int getPublicKey() {
		return e;
	}

	/*
	 * Returns n of the user
	 */
	public int getN() {
		return n;
	}

	// //// Program main /////
	public static void main(String[] args) {
		// Create objects for each entity
		RSA alice = new RSA("Alice");
		RSA bob = new RSA("Bob");
		RSA trent = new RSA("Trent");
		Random randomInput = new Random();
		traceFlag = true;

		/*
		 * Generate public-private key pairs for Alice,Bob and Trent
		 */

		alice.generatePrimes(randomInput);
		alice.generateKeysED(randomInput);
		trent.generatePrimes(randomInput);
		trent.generateKeysED(randomInput);
		bob.generatePrimes(randomInput);
		bob.generateKeysED(randomInput);

		int eAlice = alice.getPublicKey();
		int nAlice = alice.getN();

		// Generate digital certificate for Alice
		String aliceCertificate[] = trent.generateCertificate("Alice", eAlice,
				nAlice);
		System.out.println("Alice's Certificate = "
				+ Arrays.toString(aliceCertificate));

		/*
		 * Bob generates random u for Alice which is 
		 * a binary string
		 */
		String bobU = bob.generateUforBob();

		/*
		 * Alice receives u and computes h(u) Alice decrypts h(u) with her
		 * private key and gets v
		 */
		int nums1[] = new int[4];
		int j = 0;

		for (int i = 0; i < 4; i++) {
			nums1[i] = Integer.parseInt(bobU.substring(j, j + 8), 2);
			j = j + 8;
		}

		// Alice calculates h(u) : Line 210
		int hashUalice = alice.calculateHash(nums1);

		// Alice decrypts h(u) with her private key
		int v = alice
				.fastExponentiation(hashUalice, -9999, alice.getN(), false);

		// Bob will encrypt this v with Alice's public key to confirm that it is
		// authentic
		int vEncrypt = bob.fastExponentiation(v, alice.getPublicKey(),
				alice.getN(), true);

		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 215");
		System.out.println("As Integers : ");
		System.out.println("u = " + Integer.parseInt(bobU, 2));
		System.out.println("h(u) = " + hashUalice);
		System.out.println("v = D(d,h(u)) = " + v);
		System.out.println("E(e,v) = " + vEncrypt);

		System.out.println("\nAs Bits : ");
		System.out.println("u = " + bobU);
		System.out.println("h(u) = " + Integer.toBinaryString(hashUalice));
		System.out.println("v = D(d,h(u)) = " + Integer.toBinaryString(v));
		System.out.println("E(e,v) = " + Integer.toBinaryString(vEncrypt));

		System.out
				.println("----------------------------------------------------------------");
		System.out.println("Line = 219");
		System.out.println("Trace of E(e,v)\n");
		System.out.println(v + "^" + alice.getPublicKey() + " % "
				+ alice.getN() + " = " + vEncrypt);
		System.out.println("\n i | xi\t  y \t y");
		System.out.println("--------------------------");
		j = expIndex - 1;
		//trace for fast exponentiation : Bob
		for (int i = 0; i < expIndex; i++) {
			System.out.format("%2d | %s \t %4d \t %4d \n", j, arrXi[i],
					arrYsq[i], arrYmul[i]);
			j--;
		}
		if (vEncrypt == hashUalice)
			System.out.println("\nAuthenticated");
		else
			System.out.println("\nAuthentication Failed");
	}
}
