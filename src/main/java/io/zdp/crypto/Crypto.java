package io.zdp.crypto;

import org.apache.commons.lang3.math.NumberUtils;

public class Crypto {

	public static boolean isValidAccount(String accountUuid) {
		return accountUuid != null && accountUuid.startsWith(Keys.ZDP) && accountUuid.length() > 10 && NumberUtils.isCreatable(accountUuid.substring(3, 6));
	}

	public static String extractCurveNameFromPublicKey(String accountUuid) {
		return Curves.getCurveName(accountUuid.substring(3, 6));
	}

}
