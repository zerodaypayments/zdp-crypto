package io.zdp.crypto.account;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

import io.zdp.crypto.Base58;
import io.zdp.crypto.Curves;
import io.zdp.crypto.Hashing;
import io.zdp.crypto.crc.CRC8;

/**
 * Utilities related to public account uuid
 * 
 * @author sxn144
 *
 */
public class ZDPAccountUuid {

	private static final String ZERO_REPLACEMENT_FOR_BASE58 = "x";

	private static final String ZERO = "0";

	public static final String ZDP = "zdp";

	private byte[] publicKey;

	private String curve;

	public ZDPAccountUuid(byte[] publicKey, String curve) {

		this.publicKey = publicKey;
		this.curve = curve;

	}

	public String getUuid() {

		byte[] hash = Hashing.hashPublicKey(publicKey);

		CRC8 crc8 = new CRC8();
		crc8.update(hash);

		String checksum = Long.toHexString(crc8.getValue());
		checksum = StringUtils.leftPad(checksum, 2, ZERO_REPLACEMENT_FOR_BASE58);
		checksum = StringUtils.replace(checksum, ZERO, ZERO_REPLACEMENT_FOR_BASE58);

		return ZDP + Curves.getCurveIndexAsReadable(curve) + Base58.encode(hash) + checksum;

	}

	@Override
	public String toString() {
		return "ZDPAccountUuid [getUuid()=" + getUuid() + "]";
	}

	public static boolean isValidUuid(String publicAccountUuid) {

		if (StringUtils.isBlank(publicAccountUuid)) {
			return false;
		}

		if (false == StringUtils.startsWith(publicAccountUuid, ZDP)) {
			return false;
		}

		if (publicAccountUuid.length() < 20) {
			return false;
		}

		// Curve
		String curveIndex = publicAccountUuid.substring(3, 6);
		curveIndex = StringUtils.replace(curveIndex, ZERO_REPLACEMENT_FOR_BASE58, ZERO);

		while (curveIndex.startsWith(ZERO)) {
			curveIndex = StringUtils.removeStart(curveIndex, ZERO);
		}

		if (false == NumberUtils.isCreatable(curveIndex)) {
			return false;
		}

		// Checksum and hash of public key
		String checksum = publicAccountUuid.substring(publicAccountUuid.length() - 2);

		String publicKeyHash = StringUtils.removeEnd(publicAccountUuid, checksum);
		publicKeyHash = publicKeyHash.substring(6);

		checksum = StringUtils.replace(checksum, ZERO_REPLACEMENT_FOR_BASE58, ZERO);

		while (checksum.startsWith(ZERO)) {
			checksum = StringUtils.removeStart(checksum, ZERO);
		}

		// Base58 of public key hash
		byte[] hash = null;
		try {
			hash = Base58.decode(publicKeyHash);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		CRC8 crc8 = new CRC8();
		crc8.update(hash);

		String crc = Long.toHexString(crc8.getValue());
		
		while (crc.startsWith(ZERO)) {
			crc = StringUtils.removeStart(crc, ZERO);
		}
		
		if (false == crc.equals(checksum)) {
			return false;
		}

		return true;

	}
	/*
		public static int getCurve(String publicAccountUuid) {
	
		}
	
		public boolean isValid(String publicAccountUuid) {
	
		}
	
		public static byte[] hashPublicKey(byte[] pub) {
	
			pub = Hashing.whirlpool(pub);
	
			pub = DigestUtils.sha256(pub);
	
			pub = Hashing.ripemd160(pub);
	
			return pub;
	
		}
	
		public static boolean isValidAccount(String accountUuid) {
			return accountUuid != null && accountUuid.startsWith(ZDP) && accountUuid.length() > 10 && NumberUtils.isCreatable(accountUuid.substring(3, 6));
		}
	
		public static String getCurveNameFromAccountUuid(String accountUuid) {
			return Curves.getCurveName(accountUuid.substring(3, 6));
		}
	
		public static int getCurveIndexFromAccountUuid(String accountUuid) {
			return Integer.parseInt(accountUuid.substring(3, 6));
		}
	
		public static byte[] getPublicKeyHashFromAccountUuid(String uuid) {
	
			uuid = StringUtils.removeStart(uuid, ZDP);
			uuid = uuid.substring(3);
	
			try {
				return Base58.decode(uuid);
			} catch (Exception e) {
				e.printStackTrace();
			}
	
			return null;
		}
	
		public static String getZDPPublicAccountUuid(byte[] publicKeyHash, int curve) {
			return Keys.ZDP + StringUtils.leftPad(Integer.toString(curve), 3, "0") + Base58.encode(publicKeyHash);
		}
		
		public static String toZDPAccountUuid(BigInteger privKey, String curve) {
	
			byte[] pub = Keys.getPublicKeyFromPrivate(privKey, curve);
	
			pub = hashPublicKey(pub);
	
			return Crypto.getZDPPublicAccountUuid(pub, Curves.getCurveIndex(curve));
		}	
	*/
}
