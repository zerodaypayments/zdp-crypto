package io.zdp.crypto;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestBase58 extends TestCase {

	/**
	 * https://github.com/bitcoin/bitcoin/blob/b225010a808d475cbb53aeed484295f8dc8751c4/src/test/data/base58_encode_decode.json
	 * @throws Exception 
	 */
	public void test() throws Exception {

		byte[] decode = Base58.decode("");

		System.out.println(Arrays.toString(decode));

		assertTrue(Arrays.equals(new byte[] {}, Base58.decode("")));

		assertTrue(Arrays.equals(Hex.decode("61"), Base58.decode("2g")));
		assertTrue(Arrays.equals(Hex.decode("626262"), Base58.decode("a3gV")));
		assertTrue(Arrays.equals(Hex.decode("636363"), Base58.decode("aPEr")));
		assertTrue(Arrays.equals(Hex.decode("73696d706c792061206c6f6e6720737472696e67"), Base58.decode("2cFupjhnEsSn59qHXstmK2ffpLv2")));
		assertTrue(Arrays.equals(Hex.decode("00eb15231dfceb60925886b67d065299925915aeb172c06647"), Base58.decode("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L")));
		assertTrue(Arrays.equals(Hex.decode("516b6fcd0f"), Base58.decode("ABnLTmg")));
		assertTrue(Arrays.equals(Hex.decode("bf4f89001e670274dd"), Base58.decode("3SEo3LWLoPntC")));
		assertTrue(Arrays.equals(Hex.decode("572e4794"), Base58.decode("3EFU7m")));
		assertTrue(Arrays.equals(Hex.decode("ecac89cad93923c02321"), Base58.decode("EJDM8drfXA6uyA")));
		assertTrue(Arrays.equals(Hex.decode("10c8511e"), Base58.decode("Rt5zm")));
		assertTrue(Arrays.equals(Hex.decode("00000000000000000000"), Base58.decode("1111111111")));
		
		assertTrue(Base58.isBase58("2g"));
		assertTrue(Base58.isBase58("a3gV"));
		assertTrue(Base58.isBase58("aPEr"));
		assertTrue(Base58.isBase58("2cFupjhnEsSn59qHXstmK2ffpLv2"));
		assertTrue(Base58.isBase58("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"));
		assertTrue(Base58.isBase58("ABnLTmg"));
		assertTrue(Base58.isBase58("3SEo3LWLoPntC"));
		assertTrue(Base58.isBase58("3EFU7m"));
		assertTrue(Base58.isBase58("EJDM8drfXA6uyA"));
		assertTrue(Base58.isBase58("Rt5zm"));
		assertTrue(Base58.isBase58("1111111111"));

	}

}
