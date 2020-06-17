package org.springframework.security.firewall;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@State(Scope.Benchmark)
@Fork(1)
@BenchmarkMode(Mode.Throughput)
public class Gh8644StrictHttpFirewallTests {
	private static final int MAX_HEADER_SIZE = 8192;

	private static final Map<String, HttpServletRequest> requests = new HashMap<String, HttpServletRequest>()
	{{
		put("largeBody", largeBody());
		put("largeHeader", largeHeader());
		put("largeBodyAndHeader", largeBodyAndHeader());
	}};

	// To remove a use case, comment it out in the @Param annotation

	@Param({
			"largeBody",
//			"largeHeader",
//			"largeBodyAndHeader"
	})
	private String which;

	private final HttpFirewall strictHttpFirewall = new StrictHttpFirewall();
	private HttpFirewall gh8644FirewallUsingType = getGh8644StrictHttpFirewall(s -> s.codePoints().allMatch(codePoint -> { final int type = Character.getType(codePoint); return type != Character.CONTROL && type != Character.UNASSIGNED; }));
	private HttpFirewall gh8644FirewallUsingRegex = getGh8644StrictHttpFirewall(Pattern.compile("[\\p{IsAssigned}&&[^\\p{IsControl}]]*").asMatchPredicate());
	private HttpFirewall gh8644FirewallUsingCharacterMethods = getGh8644StrictHttpFirewall(s -> s.codePoints().allMatch(codePoint -> !Character.isISOControl(codePoint) && Character.isDefined(codePoint)));
	private HttpFirewall gh8644FirewallUsingNoOp = getGh8644StrictHttpFirewall(s-> true);
	private HttpFirewall gh8644FirewallUsingAllMatch = getGh8644StrictHttpFirewall(s-> s.codePoints().allMatch(v -> true));
	
	private static HttpFirewall getGh8644StrictHttpFirewall(final Predicate<String> predicate) {
		Gh8644StrictHttpFirewall firewall = new Gh8644StrictHttpFirewall();
		firewall.setAllowedHeaderNames(predicate);
		firewall.setAllowedHeaderValues(predicate);
		firewall.setAllowedParameterNames(predicate);
		return firewall;
	}

	@Benchmark
	public HttpServletRequest strictHttpFirewall() {
		return strictHttpFirewall.getFirewalledRequest(requests.get(which));
	}

	@Benchmark
	public HttpServletRequest gh8644FirewallUsingType() {
		return gh8644FirewallUsingType.getFirewalledRequest(requests.get(which));
	}

	@Benchmark
	public HttpServletRequest gh8644FirewallUsingRegex() {
		return gh8644FirewallUsingRegex.getFirewalledRequest(requests.get(which));
	}

	@Benchmark
	public HttpServletRequest gh8644FirewallUsingCharacterMethods() {
		return gh8644FirewallUsingCharacterMethods.getFirewalledRequest(requests.get(which));
	}

	@Benchmark
	public HttpServletRequest gh8644FirewallUsingNoOp() {
		return gh8644FirewallUsingNoOp.getFirewalledRequest(requests.get(which));
	}

	@Benchmark
	public HttpServletRequest gh8644FirewallUsingAllMatch() {
		return gh8644FirewallUsingAllMatch.getFirewalledRequest(requests.get(which));
	}

	private static MockHttpServletRequest largeBodyAndHeader() {
		MockHttpServletRequest large = new MockHttpServletRequest();
		MockHttpServletRequest largeBody = largeBody();
		MockHttpServletRequest largeHeader = largeHeader();
		String parameterName = largeBody.getParameterNames().nextElement();
		large.setMethod("GET");
		large.setParameter(parameterName, largeBody.getParameter(parameterName));
		large.setServerName(largeHeader.getServerName());
		large.addHeader("header", largeHeader.getHeader("header"));
		large.setRequestURI(largeHeader.getRequestURI());
		return large;
	}

	private static MockHttpServletRequest largeBody() {
		try {
			// a large request body
			byte[] parameterName = Files.readAllBytes(Paths.get("two-megabyte-request.log"));

			MockHttpServletRequest request = new MockHttpServletRequest();
			request.setParameter(new String(parameterName), "v");

			request.setMethod("GET");
			request.setServerName("host");
			request.setRequestURI("/uri");

			// NOTE: This is actually a slightly larger body than is possible in Tomcat, but
			// it is still of the same order

			return request;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static MockHttpServletRequest largeHeader() {
		try {
			// a large request body
			byte[] parameterName = Files.readAllBytes(Paths.get("two-megabyte-request.log"));

			// a large header, containing a long URI, a long Host header, and a long additional header
			byte[] hostHeader = new byte[MAX_HEADER_SIZE / 3];
			System.arraycopy(parameterName, 0, hostHeader, 0, hostHeader.length);

			byte[] anotherHeader = new byte[MAX_HEADER_SIZE / 3];
			System.arraycopy(parameterName, 0, anotherHeader, 0, hostHeader.length);

			byte[] uri = new byte[MAX_HEADER_SIZE / 3];
			System.arraycopy(parameterName, 0, uri, 0, hostHeader.length);

			MockHttpServletRequest request = new MockHttpServletRequest();
			request.setMethod("GET");
			request.setServerName(new String(hostHeader));
			request.addHeader("header", new String(anotherHeader));
			request.setRequestURI("/" + new String(uri));

			request.setParameter("p", "v");

			// NOTE: This is actually a slightly larger header than is possible in Tomcat, but
			// it is still of the same order

			return request;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) throws Exception {
		org.openjdk.jmh.Main.main(args);
	}
}
