import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Basic program that decrypts Caesar and Vigenere ciphers.
 * 
 * @author Dejan Ristic
 * 
 */
public class Decrypt {

	private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final int ALPHABET_SIZE = 26;
	private static final int ASCII_ALPHABET_BOUNDS = 90;

	private static final String CAESAR_ENCRYPTED_STRING = "YQIIKHUOEKYXQTHQJXUHRUJXUVYHIJCQDXUHUJXQDJXUIUSEDTCQDYDHECU";
	private static final float[] normalEnglishLetterFrequency = new float[] {
			8.167f, 1.492f, 2.782f, 4.253f, 12.702f, 2.228f, 2.015f, 6.094f,
			6.966f, 0.153f, 0.772f, 4.025f, 2.406f, 6.749f, 7.507f, 1.929f,
			0.095f, 5.987f, 6.327f, 9.056f, 2.758f, 0.978f, 2.360f, 0.150f,
			1.974f, 0.074f };

	private long mTime;

	public static void main(String[] args) {
		Decrypt decrypt = new Decrypt();

		decrypt.mTime = System.currentTimeMillis();
		decrypt.decryptVigenere();
		decrypt.mTime = System.currentTimeMillis() - decrypt.mTime;
		System.out.println("Time in millis: " + String.valueOf(decrypt.mTime));

		/*
		 * // Used this method to find out the key.
		 * decrypt.decryptCaesarAllKeys(CAESAR_ENCRYPTED_STRING);
		 * 
		 * // Same as above, but with the key specified. char[] solution =
		 * decrypt.decryptCaesarWithKey(CAESAR_ENCRYPTED_STRING, 10);
		 * System.out.println(); System.out.println(solution);
		 * System.out.println();
		 * 
		 * decrypt.createVigenereTable(ALPHABET);
		 */
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

	private void decryptVigenere() {
		String test = "RIKVBIYBITHUSEVAZMMLTKASRNHPNPZICSWDSVMBIYFQEZUBZPBRGYNTBURMBECZQKBMBPAWIXSOFNUZECNRAZFPHIYBQEOCTTIOXKUNOHMRGCNDDXZWIRDVDRZYAYYICPUYDHCKXQIECIEWUICJNNACSAZZZGACZHMRGXFTILFNNTSDAFGYWLNICFISEAMRMORPGMJLUSTAAKBFLTIBYXGAVDVXPCTSVVRLJENOWWFINZOWEHOSRMQDGYSDOPVXXGPJNRVILZNAREDUYBTVLIDLMSXKYEYVAKAYBPVTDHMTMGITDZRTIOVWQIECEYBNEDPZWKUNDOZRBAHEGQBXURFGMUECNPAIIYURLRIPTFOYBISEOEDZINAISPBTZMNECRIJUFUCMMUUSANMMVICNRHQJMNHPNCEPUSQDMIVYTSZTRGXSPZUVWNORGQJMYNLILUKCPHDBYLNELPHVKYAYYBYXLERMMPBMHHCQKBMHDKMTDMSSJEVWOPNGCJMYRPYQELCDPOPVPBIEZALKZWTOPRYFARATPBHGLWWMXNHPHXVKBAANAVMNLPHMEMMSZHMTXHTFMQVLILOVVULNIWGVFUCGRZZKAUNADVYXUDDJVKAYUYOWLVBEOZFGTHHSPJNKAYICWITDARZPVU";
		HashMap<String, SequenceData> finalMap = countRepeatedSequencesAndGetSpacesBetweenThem(test);

		// The most common multiple is most likely the size of our key word.
		int mostCommonMultiple = getMostCommonMultipleFromAllSequences(finalMap);

		String keyword = computeMostLikelyKeyword(mostCommonMultiple, test);

	}

	private String computeMostLikelyKeyword(int length, String encryptedString) {

		HashMap<Character, FrequencyData> frequencies = new HashMap<Character, FrequencyData>();

		// For every index in the most likely length.
		for (int i = 0; i < length; ++i) {

			// Check all Caesar cipher possibilities for the current index
			// position.
			for (int k = 0; k < 26; ++k) {
				frequencies.clear();
				char[] caesar = decryptCaesarWithKey(encryptedString, k);
				int size = caesar.length;
				// For every nth (n == length) letter in the encrypted String.
				for (int j = 0; j < encryptedString.length(); j = j + length) {

					Character key = caesar[j];
					if (k == 0 && i == 0)
						if (key == 'Z')
							System.out.print(key);

					if (frequencies.containsKey(key)) {
						FrequencyData data = frequencies.get(key);
						data.numOfOccurrences++;
						data.percentage = ((float) data.numOfOccurrences / (float) size);
						frequencies.put(key, data);
					} else {
						FrequencyData data = new FrequencyData();
						data.numOfOccurrences = 1;
						data.percentage = ((float) data.numOfOccurrences / (float) size);
						frequencies.put(key, data);
					}

				}

				if (k == 1 && i == 0)
					compareFrequencieToEnglishNormals(frequencies);

			}
		}
		return null;
	}

	private void compareFrequencieToEnglishNormals(
			HashMap<Character, FrequencyData> frequencies) {
		Iterator<Character> iterator = frequencies.keySet().iterator();

		while (iterator.hasNext()) {
			Character key = iterator.next();
			FrequencyData value = frequencies.get(key);

			System.out.println(key + " Percent:"
					+ String.valueOf(value.percentage));

		}
	}

	/**
	 * This method goes through the set of data collected when analyzing the
	 * encrypted string and returns the most common multiple shared by all
	 * repeated sequences.
	 * 
	 * @param map
	 * @return int
	 */
	private int getMostCommonMultipleFromAllSequences(
			HashMap<String, SequenceData> map) {

		Collection<SequenceData> data = map.values();

		HashMap<Integer, Integer> multiples = new HashMap<Integer, Integer>();

		for (SequenceData sequence : data) {
			if (sequence.numOfoccurrences > 1) {
				int spacing = sequence.spaceBetweenOccurrences;
				for (int i = 2; i < spacing; ++i) {
					if (isMultipleOf(i, spacing)) {
						if (multiples.containsKey(i)) {
							multiples.put(i, multiples.get(i) + 1);
						} else {
							multiples.put(i, 1);
						}
					}
				}
			}
		}

		int timesMultipleOccured = 0;
		int multiple = 0;
		for (Integer key : multiples.keySet()) {
			Integer value = multiples.get(key);
			if (value > timesMultipleOccured) {
				timesMultipleOccured = value;
				multiple = key;
			}
		}

		return multiple;
	}

	private boolean isMultipleOf(int x, int y) {
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

		printHashMap(vigenereMap);

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
		// occurrence, we need to get the spacing from the second occurence to
		// the third one.
		if (data.numOfoccurrences < 3) {
			data.lastIndex = index;
			data.spaceBetweenOccurrences = index - data.spaceBetweenOccurrences;
		} else {
			data.spaceBetweenOccurrences = index - data.lastIndex;
		}
	}

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

	public class SequenceData {
		public int spaceBetweenOccurrences;
		public int lastIndex;
		public int numOfoccurrences;
	}

	public class FrequencyData {
		public int numOfOccurrences;
		public float percentage;
	}
}