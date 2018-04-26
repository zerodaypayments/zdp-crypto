package io.zdp.crypto;

import java.math.BigInteger;

import junit.framework.TestCase;

public class TestKeys extends TestCase {

	public void test() {

		{
			BigInteger privateKey = Keys.generateRandomPrivateKey(Curves.DEFAULT_CURVE);
			assertNotNull(privateKey);
		}

		for (String curve : Curves.getAvailableCurves()) {

			BigInteger privateKey = Keys.generateRandomPrivateKey(curve);

			assertNotNull(privateKey);

			String pubKey = Keys.toPublicKey(privateKey, curve);
			assertNotNull(pubKey);
			System.out.println(pubKey);
			
			String zdpPubKey = Keys.toZDPAccountUuid(privateKey, curve);
			assertNotNull(zdpPubKey);
			System.out.println(zdpPubKey);
			
			System.out.println();

		}

	}

}
