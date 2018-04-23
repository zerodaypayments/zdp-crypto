package io.zdp.crypto;

import org.apache.commons.lang3.math.NumberUtils;

public class Crypto {

	public static boolean isValidAccount(String addr) {
		return addr != null && addr.startsWith("zdp") && addr.length() > 10 && NumberUtils.isCreatable(addr.substring(3, 6));
	}

}
