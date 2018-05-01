package io.zdp.crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestSigning extends TestCase {

	public void test() throws Exception {

		for (String curve : Curves.getAvailableCurves()) {

			BigInteger privateKey = Keys.generateRandomPrivateKey(curve);

			byte[] pubKeyBytes = Keys.getPublicKeyFromPrivate(privateKey, curve);

			assertNotNull(privateKey);

			String text = RandomStringUtils.randomAlphabetic(512);

			PrivateKey pvt = Keys.getPrivateKeyFromECBigIntAndCurve(privateKey, curve);

			System.out.println("Sign: " + text);
			
			for (int i = 0; i < 10; i++) {

				byte[] sign = Signing.sign(pvt, text);
				
				System.out.println(Hex.toHexString(sign));

				PublicKey pubKey = Keys.toPublicKey(pubKeyBytes, curve);

				boolean validSignature = Signing.isValidSignature(pubKey, text.getBytes(), sign);

				assertTrue(validSignature);
			}

		}

		for (String curve : Curves.getAvailableCurves()) {

			BigInteger privateKey = Keys.generateRandomPrivateKey(curve);

			byte[] pubKeyBytes = Keys.getPublicKeyFromPrivate(privateKey, curve);

			assertNotNull(privateKey);

			String text = RandomStringUtils.randomAlphabetic(512);

			PrivateKey pvt = Keys.getPrivateKeyFromECBigIntAndCurve(privateKey, curve);

			byte[] sign = Signing.sign(pvt, text);

			PublicKey pubKey = Keys.toPublicKey(pubKeyBytes, curve);

			boolean validSignature = Signing.isValidSignature(pubKey, "1".getBytes(), sign);

			assertFalse(validSignature);

		}

	}

}
