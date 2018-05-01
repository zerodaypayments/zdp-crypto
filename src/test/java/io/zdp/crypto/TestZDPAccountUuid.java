package io.zdp.crypto;

import io.zdp.crypto.account.ZDPAccountUuid;
import io.zdp.crypto.key.ZDPKeyPair;
import junit.framework.TestCase;

public class TestZDPAccountUuid extends TestCase {

	public void test() {

		for (int i = 0; i < 10; i++) {

			for (String curve : Curves.getAvailableCurves()) {

				ZDPKeyPair kp = ZDPKeyPair.createRandom(curve);

				//				System.out.println(kp.getZDPAccount());

				//				System.out.println();

				assertTrue(ZDPAccountUuid.isValidUuid(kp.getZDPAccount().getUuid()));

			}

		}

	}

}
