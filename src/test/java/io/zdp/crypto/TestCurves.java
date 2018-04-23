package io.zdp.crypto;

import java.util.Enumeration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.ECNamedCurveTable;

import junit.framework.TestCase;

public class TestCurves extends TestCase {

	public void test() {

		List<String> list = Curves.getAvailableCurves();
		
		System.out.println(list);

	}

}
