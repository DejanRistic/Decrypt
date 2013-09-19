import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Program that decrypts Caesar and Vigenere ciphers. The Vigenere cryptanalysis
 * does not require a key. The algorithm will figure out the most likely key's
 * and and try to decrypt the ciphertext.
 * 
 * @author Dejan Ristic
 * 
 */
public class Decrypt {

	private static final boolean DEBUG = true;

	private static final int ALPHABET_SIZE = 26;
	private static final int ASCII_ALPHABET_BOUNDS = 90;

	// From Assignment
	private static final String CAESAR_ENCRYPTED_STRING = "YQIIKHUOEKYXQTHQJXUHRUJXUVYHIJCQDXUHUJXQDJXUIUSEDTCQDYDHECU";

	// From Assignment
	private static final String VIGENERE_ENCRYPTED_STRING = "KAFZCGFCNRRKGQFVPLFCIPGJJHCCYQFGGVGJJHCCIHGDZREPAURMRHXSEELGOSRWSUGRWSPWJSXEGWTSTSEQKHZSLFCAVVYVVVVWCKCRSICQKBJXYONSUSLOAOPIYUDSWSPHCBUMJRXSUXFHOTFVRKGWIWFHGFZHGREMSIDRTSYELGYSYEBICQVVCFQUEMRLQBTEKHTOJGMYGFZREQGOIPWHXSICNXDZZGQSCQVMLVEVFSJEWHRGMXTHIYJHFHYERZCGLRARPGKMRXVWFRYOUCSILVQBRRBDNCKSDRVVVVNDTOESGGUQYSMOCRDMLLUHIERRTGYEBVRSEXMXTHVBREQCBHMONOIWMQVVVWCLFWFXADOSIEQWJOKACUGGLTNRUSUXMEGOSPCWQHVPJRPSGIPVQBJAYOMTISKDPCKLCUASRLPLIVKMERVPRGIWQQCEQVCBUWYWFCNRYJCWEMSQROTOCGVVVWAKQCCWQWCBUEPGKGJYCPCQYMLHCBUKMWDOTOGQVCTPYVUFFSKPQRVXFHUQYSMODCFOQZGFVXFHUBZXAKKSJXRHEVESJRIMFJRKGARPJOQUXMLJGJVVWNGMJXPRMSNERFJWEKYONHYILHVKFVIWTOWJGFHCIWSVRWTMMXUYVCURTRJGMXPHZREHXSICAOKQBOCHRWEKRUCQBSDHXSICDOGSKMLJVVFYEKVMFYNXVCLXMYGFKLCQGHNIFDFUFXRHPHYIKLPAPNSQKCICCDTOEHGWQBCCRRQYRGMXRZVQMQVVJJMUVVVWFLPWEIQVVCNIYUQTWSLFGDVSNOGTZKSUGRFYRWJOKXFHUSWVCHNOGXMSUKFVIHFTFVRKGARRYQFGYSUHFOEITHTSEHGQIDRVYGGCWSZQQLZSSVCRJXMEQCKXFHAGLHBHPZPWRDTHVHRRHSVPTHTMYIYYAOEHZXTRVRQROS";

	// Another string to test vigenere with
	private static final String VIGENERE_ENCRYPTED_STRING_TWO = "RIKVBIYBITHUSEVAZMMLTKASRNHPNPZICSWDSVMBIYFQEZUBZPBRGYNTBURMBECZQKBMBPAWIXSOFNUZECNRAZFPHIYBQEOCTTIOXKUNOHMRGCNDDXZWIRDVDRZYAYYICPUYDHCKXQIECIEWUICJNNACSAZZZGACZHMRGXFTILFNNTSDAFGYWLNICFISEAMRMORPGMJLUSTAAKBFLTIBYXGAVDVXPCTSVVRLJENOWWFINZOWEHOSRMQDGYSDOPVXXGPJNRVILZNAREDUYBTVLIDLMSXKYEYVAKAYBPVTDHMTMGITDZRTIOVWQIECEYBNEDPZWKUNDOZRBAHEGQBXURFGMUECNPAIIYURLRIPTFOYBISEOEDZINAISPBTZMNECRIJUFUCMMUUSANMMVICNRHQJMNHPNCEPUSQDMIVYTSZTRGXSPZUVWNORGQJMYNLILUKCPHDBYLNELPHVKYAYYBYXLERMMPBMHHCQKBMHDKMTDMSSJEVWOPNGCJMYRPYQELCDPOPVPBIEZALKZWTOPRYFARATPBHGLWWMXNHPHXVKBAANAVMNLPHMEMMSZHMTXHTFMQVLILOVVULNIWGVFUCGRZZKAUNADVYXUDDJVKAYUYOWLVBEOZFGTHHSPJNKAYICWITDARZPVU";

	private static final float[] normalEnglishLetterFrequency = new float[] {
			8.167f, 1.492f, 2.782f, 4.253f, 12.702f, 2.228f, 2.015f, 6.094f,
			6.966f, 0.153f, 0.772f, 4.025f, 2.406f, 6.749f, 7.507f, 1.929f,
			0.095f, 5.987f, 6.327f, 9.056f, 2.758f, 0.978f, 2.360f, 0.150f,
			1.974f, 0.074f };

	private long mTime;

	public static void main(String[] args) {
		Decrypt decrypt = new Decrypt();

		// Start timer to keep track of execution time.
		decrypt.mTime = System.currentTimeMillis();

		// Caesar Cryptanalysis
		System.out
				.println("----------------------Caesar-------------------------");
		decrypt.decryptCaesarAllKeys(CAESAR_ENCRYPTED_STRING);
		System.out.println();
		char[] solution = decrypt.decryptCaesarWithKey(CAESAR_ENCRYPTED_STRING,
				10);
		System.out.println("KEY: 10 " + String.copyValueOf(solution));

		// Vigenere Cryptanalysis
		System.out
				.println("----------------------Vigenere-------------------------");
		decrypt.decryptVigenereWithNoKey(VIGENERE_ENCRYPTED_STRING);

		decrypt.mTime = System.currentTimeMillis() - decrypt.mTime;

		System.out.println();
		System.out.println("Time in millis: " + String.valueOf(decrypt.mTime));

	}

	/**
	 * This method loops through all shifts possible using a simple Caesar
	 * cipher(1-26). Then it will print each decrypted string after the shift
	 * has been completed. The result is 26 decrypted strings, which I can then
	 * look through and figure out which one is an English sentence.
	 * 
	 * @param encryptedString
	 */
	private void decryptCaesarAllKeys(String encryptedString) {
		StringBuilder solution = new StringBuilder();
		char[] encryptedChars = encryptedString.toCharArray();

		// Loop through all possible shifts in the alphabet.
		for (int j = 1; j <= ALPHABET_SIZE; j++) {
			// Loop through the encrypted message and shift each character.
			for (int i = 0; i < encryptedChars.length; i++) {
				char shift = (char) (encryptedChars[i] + j);
				if (shift > ASCII_ALPHABET_BOUNDS)
					solution.append((char) (shift - ALPHABET_SIZE));
				else
					solution.append(shift);
			}

			System.out.print(solution.toString());
			System.out.println("   SHIFT = " + j);

			// clear the string builder.
			solution.setLength(0);
		}
	}

	/**
	 * This method is used to print the absolute decrypted message given a
	 * string encrypted with a simple Caesar cipher. It requires the key to
	 * shift by as a char. The result is a single decrypted string.
	 * 
	 * @param encryptedString
	 * @param key
	 */
	private char[] decryptCaesarWithKey(String encryptedString, int key) {
		StringBuilder solution = new StringBuilder();
		char[] encryptedChars = encryptedString.toCharArray();

		// Loop through the encrypted message and shift each character.
		for (int i = 0; i < encryptedChars.length; i++) {
			char shift = (char) (encryptedChars[i] + key);
			if (shift > ASCII_ALPHABET_BOUNDS)
				solution.append((char) (shift - ALPHABET_SIZE));
			else
				solution.append(shift);
		}
		return solution.toString().toCharArray();
	}

	private void decryptVigenereWithNoKey(String ciphertext) {

		HashMap<String, SequenceData> finalMap = countRepeatedSequencesAndGetSpacesBetweenThem(ciphertext);

		// The most common multiple is most likely the size of our key word, but
		// for safety we allow to check the nth most common multiples just in
		// case the most common one was not correct.
		int[] mostCommonMultiples = getMostCommonFactorsFromAllSequences(
				finalMap, 4);

		for (int i = 0; i < mostCommonMultiples.length; ++i) {
			char keyword[] = computeMostLikelyKeyword(mostCommonMultiples[i],
					ciphertext);
			decryptVigenereWithKey(ciphertext, String.copyValueOf(keyword));
		}

	}

	private void decryptVigenereWithKey(String text, final String key) {
		String res = "";
		text = text.toUpperCase();
		for (int i = 0, j = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c < 'A' || c > 'Z')
				continue;
			res += (char) ((c - key.charAt(j) + 26) % 26 + 'A');
			j = ++j % key.length();
		}
		System.out.println(res);
	}

	private char[] computeMostLikelyKeyword(int length, String encryptedString) {

		// HashMap to store our frequency analysis data.
		HashMap<Character, FrequencyData> frequencies = new HashMap<Character, FrequencyData>();

		// Results for chiSquared computations.
		double[] chiSquaredResults = null;

		// The final resulting secret key.
		char[] secretKey = new char[length];

		// For every index in the most likely length.
		for (int i = 0; i < length; ++i) {

			chiSquaredResults = new double[26];

			// Check all Caesar cipher possibilities for the current index
			// position.
			for (int k = 0; k < 26; ++k) {

				double totalChiScore = 0;

				frequencies.clear();

				// Decrypt our encrypted string with the shift k.
				char[] caesar = decryptCaesarWithKey(encryptedString, k);

				// For every nth (n == most likely length of keyword) letter in
				// the encrypted String.
				for (int j = i; j < encryptedString.length(); j = j + length) {

					// Get that key after the Caesar shift k.
					Character key = caesar[j];

					// Count the number of occurrences said key appears in the
					// set of all nth characters.
					if (frequencies.containsKey(key)) {
						FrequencyData data = frequencies.get(key);
						data.numOfOccurrences++;
						frequencies.put(key, data);
					} else {
						FrequencyData data = new FrequencyData();
						data.numOfOccurrences = 1;
						frequencies.put(key, data);
					}

				}

				// After all occurrences are counted, we can now use the chi
				// squared function to add to our total chi score for this
				// iteration.
				for (Character key : frequencies.keySet()) {

					FrequencyData data = frequencies.get(key);
					data.chiSquared = computeChiSquared(data.numOfOccurrences,
							frequencies.size(), key);
					totalChiScore += data.chiSquared;

				}

				// Keep the total chi scores from all 25 shifts, so we can find
				// the lowest later.
				chiSquaredResults[k] += totalChiScore;

			}

			// Now we can go through all the chiScores and find the lowest one
			// out of the 25 possible shifts. The lowest score is most
			// comparable to English.
			int winningIndex = 0;
			double min = Integer.MAX_VALUE;
			for (int l = 0; l < chiSquaredResults.length; ++l) {
				if (chiSquaredResults[l] < min) {
					min = chiSquaredResults[l];
					winningIndex = l;
				}
			}

			// Manipulate the char a bit, so we have it in a form that makes it
			// easy to use with the rest of our code.
			char secretChar = (char) ('A' + (winningIndex == 0 ? 0
					: (char) (26 - winningIndex)));

			// Finally store the ith character of the keyword and repeat untill
			// length.
			secretKey[i] = secretChar;
		}

		System.out.println("KEYWORD: " + String.copyValueOf(secretKey));

		return secretKey;
	}

	/**
	 * The Chi-squared Statistic is a measure of how similar two categorical
	 * probability distributions are. If the two distributions are identical,
	 * the chi-squared statistic is 0, if the distributions are very different,
	 * some higher number will result
	 * 
	 * @param numOfOccurences
	 * @param lengthOfCipher
	 * @param englishLetter
	 * @return
	 */
	private double computeChiSquared(int numOfOccurences, int lengthOfCipher,
			char englishLetter) {

		int englishIndex = englishLetter - 65;
		double englishNormal = (normalEnglishLetterFrequency[englishIndex] / 100);
		double factor = lengthOfCipher * englishNormal;

		double chiSquared = Math.pow(numOfOccurences - factor, 2.0) / factor;
		return chiSquared;
	}

	/**
	 * This method goes through the set of data collected when analyzing the
	 * encrypted string and returns the most common factors shared by all
	 * repeated sequences.
	 * 
	 * @param map
	 * @return int []
	 */
	@SuppressWarnings("unchecked")
	private int[] getMostCommonFactorsFromAllSequences(
			HashMap<String, SequenceData> map, int maxFactors) {

		Collection<SequenceData> data = map.values();

		HashMap<Integer, Integer> factors = new HashMap<Integer, Integer>();

		for (SequenceData sequence : data) {
			if (sequence.numOfoccurrences > 1) {
				int spacing = sequence.spaceBetweenOccurrences;
				for (int i = 2; i < spacing; ++i) {
					if (isFactorOf(i, spacing)) {
						if (factors.containsKey(i)) {
							factors.put(i, factors.get(i) + 1);
						} else {
							factors.put(i, 1);
						}
					}
				}
			}
		}

		Map<Integer, Integer> sorted = sortByComparator(factors);

		int[] mostCommonFactors = new int[maxFactors];

		if (DEBUG) {
			System.out.println(maxFactors + " Most Common Factors");
			System.out.println("--------------------------");
		}
		for (int i = 0; i < mostCommonFactors.length; ++i) {
			Entry<Integer, Integer> entry = (Entry<Integer, Integer>) sorted
					.entrySet().toArray()[i];
			mostCommonFactors[i] = entry.getKey();

			if (DEBUG)
				System.out.println("Factor : " + entry.getKey()
						+ " Occurences : " + entry.getValue());
		}
		if (DEBUG)
			System.out.println();

		return mostCommonFactors;
	}

	/**
	 * Helper method to sort a HashMap by comparator.
	 * 
	 * @param unsortMap
	 * @param order
	 * @return
	 */
	private static Map<Integer, Integer> sortByComparator(
			Map<Integer, Integer> unsortMap) {

		List<Entry<Integer, Integer>> list = new LinkedList<Entry<Integer, Integer>>(
				unsortMap.entrySet());

		// Sorting the list based on values
		Collections.sort(list, new Comparator<Entry<Integer, Integer>>() {
			public int compare(Entry<Integer, Integer> o1,
					Entry<Integer, Integer> o2) {
				return o2.getValue().compareTo(o1.getValue());
			}
		});

		// Maintaining insertion order with the help of LinkedList
		Map<Integer, Integer> sortedMap = new LinkedHashMap<Integer, Integer>();
		for (Entry<Integer, Integer> entry : list) {
			sortedMap.put(entry.getKey(), entry.getValue());
		}

		return sortedMap;
	}

	/**
	 * Helper method to determine if x is a factor of y.
	 * 
	 * @param x
	 * @param y
	 * @return
	 */
	private boolean isFactorOf(int x, int y) {
		if (y % x == 0)
			return true;
		return false;
	}

	/**
	 * This method is used to iterate through the entire encrypted string and
	 * put all sequences that are repeated throughout the string in a HashMap.
	 * The HashMap stores how many times each sequence has occurred in the
	 * encrypted string and the spacing between the last two occurrences of the
	 * sequence.
	 * 
	 * @param encryptedString
	 */
	private HashMap<String, SequenceData> countRepeatedSequencesAndGetSpacesBetweenThem(
			String encryptedString) {

		// denotes the minimum length that a sequence can be. A sequence
		// is defined as any substring in the encrypted string that is greater
		// than 1. the chars in the substring must be sequential.
		int minSequenceLenth = 3;

		// HashMap that will store all the data necessary for the Vigenere
		// cipher.
		HashMap<String, SequenceData> vigenereMap = new HashMap<String, SequenceData>();

		// Iterate through all possible sizes of sequences down to the minimum
		// defined above.
		for (int j = encryptedString.length(); j >= minSequenceLenth; --j) {

			// For each size above the minimum, iterate through the encrypted
			// string and count sequence occurrences and the spacing between
			// them.
			for (int i = 0; i < encryptedString.length(); ++i) {

				// Keep in bounds of the string.
				if (encryptedString.length() - i > (j - 1)) {

					// Construct our sequence
					String sequence = encryptedString.substring(i, i + j);

					// Check to see if we already have this sequence in our map.
					// If not, we create a brand new sequence.
					if (vigenereMap.containsKey(sequence)) {
						SequenceData data = vigenereMap.get(sequence);
						updateSequenceData(data, (i + j));
						vigenereMap.put(sequence, data);
					} else {
						SequenceData pair = new SequenceData();
						pair.numOfoccurrences = 1;
						pair.spaceBetweenOccurrences = i + j;
						vigenereMap.put(sequence, pair);
					}
				}
			}
		}

		if (DEBUG) {
			System.out.println("Sequences and Spacing");
			System.out.println("--------------------------");
			printHashMap(vigenereMap);
			System.out.println();

		}
		return vigenereMap;
	}

	/**
	 * Helper method that updates the sequence data when a new occurrence of the
	 * sequence is found.
	 * 
	 * @param data
	 * @param index
	 */
	private void updateSequenceData(SequenceData data, int index) {
		data.numOfoccurrences++;

		// If there is only 2 occurrences of the sequence, then we do not have
		// to use the last occurrences index. This is because the spacing starts
		// at the index the first occurrence was found. If there is a third
		// occurrence, we need to get the spacing from the second occurrence to
		// the third one.
		if (data.numOfoccurrences < 3) {
			data.lastIndex = index;
			data.spaceBetweenOccurrences = index - data.spaceBetweenOccurrences;
		} else {
			data.spaceBetweenOccurrences = index - data.lastIndex;
		}
	}

	/**
	 * Helper method to print a HashMap of String, SequenceData.
	 * 
	 * @param map
	 */
	private void printHashMap(HashMap<String, SequenceData> map) {
		Iterator<String> iterator = map.keySet().iterator();

		while (iterator.hasNext()) {
			String key = iterator.next();
			SequenceData value = map.get(key);

			if (value.numOfoccurrences > 1) {
				System.out.println(key + " " + value.numOfoccurrences
						+ " Spacing: " + value.spaceBetweenOccurrences);
			}
		}
	}

	/**
	 * Helper method to generate the Vigenere table form scratch.
	 * 
	 * @param alphabet
	 * @return
	 */
	private char[][] createVigenereTable(String alphabet) {
		char[][] table = new char[ALPHABET_SIZE][ALPHABET_SIZE];

		// loop through the entire 26x26 matrix.
		for (int i = 0; i < ALPHABET_SIZE; ++i) {
			for (int j = 0; j < ALPHABET_SIZE; ++j) {

				// shift the alphabet depending on the row.
				char[] shiftedAlphabet = decryptCaesarWithKey(alphabet, i);

				// populate our table with the proper value after the alphabet
				// has been shifted.
				table[i][j] = shiftedAlphabet[j];
			}
		}

		print2DMatrix(table);
		return table;
	}

	/**
	 * Helper method to print out a 2D matrix with "good" spacing.
	 * 
	 * @param matrix
	 */
	private void print2DMatrix(char[][] matrix) {
		for (int x = 0; x < ALPHABET_SIZE; ++x) {
			for (int y = 0; y < ALPHABET_SIZE; ++y) {
				System.out.print(matrix[x][y] + " ");
			}
			System.out.println();
		}
	}

	/**
	 * Helper class that stores sequence data.
	 * 
	 * @author Dejan Ristic
	 * 
	 */
	public class SequenceData {
		public int spaceBetweenOccurrences;
		public int lastIndex;
		public int numOfoccurrences;
	}

	/**
	 * Helper class that stores frequency data.
	 * 
	 * @author Dejan Ristic
	 * 
	 */
	public class FrequencyData {
		public int numOfOccurrences;
		public double chiSquared;
	}
}