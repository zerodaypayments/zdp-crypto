package io.zdp.crypto;

import junit.framework.TestCase;

public class TestCrypto extends TestCase {

	public void test() {

		assertFalse(Crypto.isValidAccount(null));
		assertFalse(Crypto.isValidAccount(""));
		assertFalse(Crypto.isValidAccount(" "));
		assertFalse(Crypto.isValidAccount("zdp"));
		assertFalse(Crypto.isValidAccount("zdp23f"));
		assertFalse(Crypto.isValidAccount("zdps22312312"));
		assertTrue(Crypto.isValidAccount("zdp221dfasdf312312"));

	}

}
