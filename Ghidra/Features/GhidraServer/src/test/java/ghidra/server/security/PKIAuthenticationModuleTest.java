/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.server.security;

import static org.junit.Assert.*;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.x500.X500Principal;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.remote.GhidraPrincipal;
import ghidra.framework.remote.SignatureCallback;
import ghidra.net.DefaultKeyManagerFactory;
import ghidra.net.DefaultTrustManagerFactory;
import ghidra.net.PKIUtils;
import ghidra.server.RepositoryManager;
import utilities.util.FileUtilities;

public class PKIAuthenticationModuleTest extends AbstractGenericTest {

	private static final String TEST_PASSWORD = "test-password";
	private static final String VICTIM_USERNAME = "victim";
	private static final String VICTIM_DN = "CN=Victim";

	private static File testDir;
	private static File caCertFile;
	private static PrivateKeyEntry victimEntry;
	private static PrivateKeyEntry attackerEntry;

	private RepositoryManager repositoryManager;
	private PKIAuthenticationModule module;
	private String previousCaCertsPath;
	private String previousKeyStorePath;
	private String previousKeyStorePreference;
	private X500Principal previousDefaultIdentity;

	@BeforeClass
	public static void setUpClass() throws Exception {
		testDir = createTempDirectory("PKIAuthenticationModuleTest");

		KeyStore caKeyStore = PKIUtils.createKeyStore("ca", "CN=Test CA", 365, null,
			new File(testDir, "ca.p12"), "PKCS12", null, TEST_PASSWORD.toCharArray());
		PrivateKeyEntry caEntry = (PrivateKeyEntry) caKeyStore.getEntry("ca",
			new KeyStore.PasswordProtection(TEST_PASSWORD.toCharArray()));
		victimEntry = PKIUtils.createKeyEntry("victim", VICTIM_DN, 365, caEntry, null,
			"PKCS12", null, TEST_PASSWORD.toCharArray());
		attackerEntry = PKIUtils.createKeyEntry("attacker", "CN=Attacker", 365, caEntry, null,
			"PKCS12", null, TEST_PASSWORD.toCharArray());

		caCertFile = new File(testDir, "ca.pem");
		PKIUtils.exportX509Certificates(new Certificate[] { caEntry.getCertificate() },
			caCertFile);
	}

	@AfterClass
	public static void tearDownClass() {
		if (testDir != null) {
			FileUtilities.deleteDir(testDir);
		}
	}

	@Before
	public void setUp() throws Exception {
		previousCaCertsPath =
			System.getProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY);
		previousKeyStorePath = System.getProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
		previousKeyStorePreference =
			Preferences.removeProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
		previousDefaultIdentity = getDefaultIdentity();

		System.setProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY,
			caCertFile.getAbsolutePath());
		invalidateTrustManagers();
		DefaultTrustManagerFactory.getTrustManagers();

		System.clearProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
		DefaultKeyManagerFactory.setDefaultIdentity(new X500Principal("CN=GhidraServer"));
		assertNull(DefaultKeyManagerFactory.getPreferredKeyStore());
		assertTrue(DefaultKeyManagerFactory.initialize());
		assertTrue(DefaultKeyManagerFactory.usingGeneratedSelfSignedCertificate());

		File repositoryRoot = new File(testDir, "repositories-" + System.nanoTime());
		assertTrue(repositoryRoot.mkdir());
		repositoryManager = new RepositoryManager(repositoryRoot, false, 0, false);
		repositoryManager.getUserManager().addUser(VICTIM_USERNAME,
			new X500Principal(VICTIM_DN));

		module = new PKIAuthenticationModule(false);
	}

	@After
	public void tearDown() throws Exception {
		if (repositoryManager != null) {
			repositoryManager.dispose();
		}
		if (previousCaCertsPath == null) {
			System.clearProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY);
		}
		else {
			System.setProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY,
				previousCaCertsPath);
		}
		invalidateTrustManagers();

		DefaultKeyManagerFactory.setDefaultIdentity(previousDefaultIdentity);
		Preferences.setProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY,
			previousKeyStorePreference);
		if (previousKeyStorePath == null) {
			System.clearProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY);
		}
		else {
			System.setProperty(DefaultKeyManagerFactory.KEYSTORE_PATH_PROPERTY, previousKeyStorePath);
		}
		DefaultKeyManagerFactory.invalidateKeyManager();
	}

	@Test
	public void testValidSignatureAuthenticates() throws Exception {
		SignatureCallback sigCb = getSignatureCallback();
		sigCb.sign(getCertificateChain(victimEntry), sign(victimEntry, sigCb.getToken()));

		assertEquals(VICTIM_USERNAME,
			module.authenticate(repositoryManager.getUserManager(), getSubject(),
				new Callback[] { sigCb }));
	}

	@Test
	public void testMissingSignatureRejected() throws Exception {
		SignatureCallback sigCb = getSignatureCallback();
		sigCb.sign(getCertificateChain(victimEntry), null);

		FailedLoginException e = assertThrows(FailedLoginException.class,
			() -> module.authenticate(repositoryManager.getUserManager(), getSubject(),
				new Callback[] { sigCb }));
		assertEquals("Client signature required", e.getMessage());
	}

	@Test
	public void testSignatureFromDifferentKeyRejected() throws Exception {
		SignatureCallback sigCb = getSignatureCallback();
		sigCb.sign(getCertificateChain(victimEntry), sign(attackerEntry, sigCb.getToken()));

		FailedLoginException e = assertThrows(FailedLoginException.class,
			() -> module.authenticate(repositoryManager.getUserManager(), getSubject(),
				new Callback[] { sigCb }));
		assertEquals("Incorrect signature", e.getMessage());
	}

	private SignatureCallback getSignatureCallback() {
		Callback[] callbacks = module.getAuthenticationCallbacks();
		assertEquals(1, callbacks.length);
		assertTrue(callbacks[0] instanceof SignatureCallback);
		return (SignatureCallback) callbacks[0];
	}

	private Subject getSubject() {
		Subject subject = new Subject();
		subject.getPrincipals().add(new GhidraPrincipal(VICTIM_USERNAME));
		return subject;
	}

	private static X509Certificate[] getCertificateChain(PrivateKeyEntry entry) {
		Certificate[] certificates = entry.getCertificateChain();
		X509Certificate[] chain = new X509Certificate[certificates.length];
		for (int i = 0; i < certificates.length; i++) {
			chain[i] = (X509Certificate) certificates[i];
		}
		return chain;
	}

	private static byte[] sign(PrivateKeyEntry entry, byte[] token) throws Exception {
		X509Certificate certificate = (X509Certificate) entry.getCertificate();
		Signature signature = Signature.getInstance(certificate.getSigAlgName());
		signature.initSign(entry.getPrivateKey());
		signature.update(token);
		return signature.sign();
	}

	private static void invalidateTrustManagers() throws Exception {
		Method method =
			DefaultTrustManagerFactory.class.getDeclaredMethod("invalidateTrustManagers");
		method.setAccessible(true);
		method.invoke(null);
	}

	private static X500Principal getDefaultIdentity() throws Exception {
		Field field = DefaultKeyManagerFactory.class.getDeclaredField("defaultIdentity");
		field.setAccessible(true);
		return (X500Principal) field.get(null);
	}
}
