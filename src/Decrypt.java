/**
 * Basic program that decrypts Caesar and Vignere ciphers.
 * 
 * @author Dejan Ristic
 * 
 */
public class Decrypt {

	private static final String CAESAR_STRING = "YQIIKHUOEKYXQTHQJXUHRUJXUVYHIJCQDXUHUJXQDJXUIUSEDTCQDYDHECU";
	private static final int ALPHABET_SIZE = 26;
	private static final int ASCII_ALPHABET_BOUNDS = 90;

	public static void main(String[] args) {
		Decrypt decrypt = new Decrypt();

		// Used this method to find out the key.
		decrypt.decryptCaesarAllKeys(CAESAR_STRING);
		// Same as above, but with the key specified.
		decrypt.decryptCaesarWithKey(CAESAR_STRING, 10);

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
	private void decryptCaesarWithKey(String encryptedString, int key) {
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

		System.out.print(solution.toString());
		System.out.println("   SHIFT = " + key);

		// clear the string builder.
		solution.setLength(0);
	}
}