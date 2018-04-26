package io.zdp.crypto.key;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.zdp.crypto.Base58;
import io.zdp.crypto.Keys;
import io.zdp.crypto.Signing;

@SuppressWarnings("serial")
public class ZDPKeyPair implements Serializable {

	private static final Logger log = LoggerFactory.getLogger(ZDPKeyPair.class);

	private BigInteger bi;

	private String curve;

	private ZDPKeyPair() {
	}

	public static ZDPKeyPair createFromPrivateKeyBigInteger(BigInteger bigint, String curve) {
		ZDPKeyPair pair = new ZDPKeyPair();
		pair.bi = bigint;
		pair.curve = curve;
		return pair;
	}

	public static ZDPKeyPair createFromPrivateKeyBase58(String privateKeyB58, String curve) {

		BigInteger privKey = Keys.toBigIntegerFromPrivateKeyBase58(privateKeyB58);

		ZDPKeyPair pair = new ZDPKeyPair();
		pair.bi = privKey;
		pair.curve = curve;

		return pair;

	}

	public static ZDPKeyPair createRandom(String curve) {

		final BigInteger priv = Keys.generateRandomPrivateKey(curve);

		ZDPKeyPair pair = new ZDPKeyPair();
		pair.bi = priv;
		pair.curve = curve;

		return pair;

	}

	public String getPrivateKeyAsBase58() {
		return Keys.toZDPPrivateKey(bi);
	}

	public BigInteger getPrivateKeyAsBigInteger() {
		return bi;
	}

	public PrivateKey getPrivateKeyAsPrivateKey() {
		return Keys.getPrivateKeyFromECBigIntAndCurve(bi, curve);
	}

	private byte[] generatePublicKey() {
		if (bi == null) {
			throw new IllegalArgumentException("PrivateKey is null");
		}

		return Keys.getPublicKeyFromPrivate(bi, curve);
	}

	public byte[] getPublicKeyAsBytes() {
		return generatePublicKey();
	}

	public PublicKey getPublicKeyAsPublicKey() {
		try {
			return Keys.toPublicKey(getPublicKeyAsBytes(), curve);
		} catch (Exception e) {
			log.error("Error: ", e);
		}
		return null;
	}

	public String getPublicKeyAsBase58() {
		return Base58.encode(getPublicKeyAsBytes());
	}

	public String getAccountUuid() {
		return Keys.toZDPAccountUuid(bi, curve);
	}

	public byte[] sign(byte[] data) throws Exception {
		return Signing.sign(getPrivateKeyAsPrivateKey(), data);
	}

	public byte[] sign(String data) throws Exception {
		return Signing.sign(getPrivateKeyAsPrivateKey(), data);
	}

}
