package io.zdp.crypto;

public class Crypto {

	public static boolean isValidAccount(String addr) {
		return addr != null && addr.startsWith(Keys.ZDP00) && addr.length() > 30 && addr.length() < 40;
	}

}
