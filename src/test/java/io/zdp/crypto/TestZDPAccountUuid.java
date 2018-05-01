package io.zdp.crypto;

import io.zdp.crypto.account.ZDPAccountUuid;
import io.zdp.crypto.key.ZDPKeyPair;
import junit.framework.TestCase;

public class TestZDPAccountUuid extends TestCase {

	public void test() {

		for (int i = 0; i < 10; i++) {

			for (String curve : Curves.getAvailableCurves()) {

				ZDPKeyPair kp = ZDPKeyPair.createRandom(curve);

				String uuid = kp.getZDPAccount().getUuid();

				assertEquals(curve, kp.getZDPAccount().getCurve());

				assertTrue(ZDPAccountUuid.isValidUuid(uuid));

				ZDPAccountUuid zu = new ZDPAccountUuid(uuid);

				assertEquals(curve, zu.getCurve());

				assertTrue(uuid.contains(Base58.encode(zu.getPublicKeyHash())));
				assertTrue(uuid.contains(Base58.encode(kp.getZDPAccount().getPublicKeyHash())));

			}

		}

	}

}
