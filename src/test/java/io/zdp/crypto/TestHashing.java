package io.zdp.crypto;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestHashing extends TestCase {

	public void testRipemd160() {

		assertEquals("9c1185a5c5e9fc54612808977ee8f548b2258d31", Hex.toHexString(Hashing.ripemd160("")));
		assertEquals("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", Hex.toHexString(Hashing.ripemd160("a")));
		assertEquals("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", Hex.toHexString(Hashing.ripemd160("abc")));
		assertEquals("5d0689ef49d2fae572b881b123a85ffa21595f36", Hex.toHexString(Hashing.ripemd160("message digest")));
		assertEquals("f71c27109c692c1b56bbdceb5b9d2865b3708dbc", Hex.toHexString(Hashing.ripemd160("abcdefghijklmnopqrstuvwxyz")));
		assertEquals("9b752e45573d4b39f4dbd3323cab82bf63326bfb", Hex.toHexString(Hashing.ripemd160("12345678901234567890123456789012345678901234567890123456789012345678901234567890")));
		assertEquals("52783243c1697bdbe16d37f97f68f08325dc1528", Hex.toHexString(Hashing.ripemd160(StringUtils.repeat("a", 1000000))));

	}

	public void testWhirlpool() {

		assertEquals("b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35", Hex.toHexString(Hashing.whirlpool("The quick brown fox jumps over the lazy dog")));
		assertEquals("e006fb0f4817f50191794177e61a575057cbd486ce2d28d882aa23624440ada57c0913cc7b016f6315f612a9320203e0b5fa32b510c42d03bfc7b96c2769a740", Hex.toHexString(Hashing.whirlpool("Test vector from febooti.com")));
		assertEquals("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", Hex.toHexString(Hashing.whirlpool("")));

	}

}
