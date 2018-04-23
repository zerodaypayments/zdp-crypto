package io.zdp.crypto;

import java.security.SecureRandom;

public class Random {

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public static SecureRandom getSecureRandom() {
		return SECURE_RANDOM;
	}

}
