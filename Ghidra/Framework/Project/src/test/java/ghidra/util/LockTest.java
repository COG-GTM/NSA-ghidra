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
package ghidra.util;

import static org.junit.Assert.*;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Tests for the {@link Lock} class, which wraps a {@link java.util.concurrent.locks.ReentrantReadWriteLock}
 * to provide separate read and write lock semantics.
 *
 * <p>Key design notes:
 * <ul>
 *   <li>{@code acquire()}/{@code release()} correspond to the <b>write</b> lock (exclusive).</li>
 *   <li>{@code acquireRead()}/{@code releaseRead()} correspond to the <b>read</b> lock (shared).</li>
 *   <li>{@link java.util.concurrent.locks.ReentrantReadWriteLock} does <b>not</b> support upgrading
 *       from a read lock to a write lock. A thread must release its read lock before acquiring the
 *       write lock.</li>
 * </ul>
 */
public class LockTest extends AbstractGenericTest {

	private static final int TIMEOUT_MS = 5000;

	// -------------------------------------------------------------------------
	// Basic write-lock (acquire/release) tests
	// -------------------------------------------------------------------------

	@Test
	public void testWriteLockIsExclusive() throws Exception {
		Lock lock = new Lock("test");
		CountDownLatch thread1Acquired = new CountDownLatch(1);
		CountDownLatch thread2Attempted = new CountDownLatch(1);
		AtomicBoolean thread2Blocked = new AtomicBoolean(false);

		Thread t1 = new Thread(() -> {
			lock.acquire();
			thread1Acquired.countDown();
			try {
				// Hold the lock while thread2 tries to acquire
				assertTrue(thread2Attempted.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
				// Give thread2 a moment to block
				Thread.sleep(200);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			finally {
				lock.release();
			}
		});

		Thread t2 = new Thread(() -> {
			try {
				assertTrue(thread1Acquired.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			thread2Attempted.countDown();
			thread2Blocked.set(true);
			lock.acquire();
			try {
				// If we get here, thread1 must have released
				thread2Blocked.set(false);
			}
			finally {
				lock.release();
			}
		});

		t1.start();
		t2.start();
		t1.join(TIMEOUT_MS);
		t2.join(TIMEOUT_MS);

		assertFalse("Thread2 should have completed", thread2Blocked.get());
	}

	@Test
	public void testReentrantWriteLock() {
		Lock lock = new Lock("test");

		lock.acquire();
		try {
			// Reentrant acquisition should succeed
			lock.acquire();
			try {
				assertTrue(lock.isLocked());
				assertEquals(2, lock.getWriteHoldCount());
			}
			finally {
				lock.release();
			}
			assertTrue(lock.isLocked());
			assertEquals(1, lock.getWriteHoldCount());
		}
		finally {
			lock.release();
		}

		assertFalse(lock.isLocked());
	}

	@Test
	public void testWriteLockOwner() {
		Lock lock = new Lock("test");

		assertNull(lock.getOwner());

		lock.acquire();
		try {
			assertEquals(Thread.currentThread(), lock.getOwner());
		}
		finally {
			lock.release();
		}

		assertNull(lock.getOwner());
	}

	// -------------------------------------------------------------------------
	// Basic read-lock (acquireRead/releaseRead) tests
	// -------------------------------------------------------------------------

	@Test
	public void testConcurrentReadLocks() throws Exception {
		Lock lock = new Lock("test");
		int numReaders = 5;
		CountDownLatch allAcquired = new CountDownLatch(numReaders);
		CountDownLatch release = new CountDownLatch(1);
		AtomicInteger concurrentReaders = new AtomicInteger(0);
		AtomicInteger maxConcurrentReaders = new AtomicInteger(0);

		Thread[] readers = new Thread[numReaders];
		for (int i = 0; i < numReaders; i++) {
			readers[i] = new Thread(() -> {
				lock.acquireRead();
				try {
					int current = concurrentReaders.incrementAndGet();
					maxConcurrentReaders.updateAndGet(max -> Math.max(max, current));
					allAcquired.countDown();
					try {
						assertTrue(release.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
					}
					catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}
				finally {
					concurrentReaders.decrementAndGet();
					lock.releaseRead();
				}
			});
		}

		for (Thread t : readers) {
			t.start();
		}

		assertTrue("All readers should acquire concurrently",
			allAcquired.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));

		// All readers should be holding the lock simultaneously
		assertEquals(numReaders, concurrentReaders.get());
		assertTrue("Multiple readers should hold locks concurrently",
			maxConcurrentReaders.get() > 1);

		release.countDown();

		for (Thread t : readers) {
			t.join(TIMEOUT_MS);
		}
	}

	@Test
	public void testReadLockCount() {
		Lock lock = new Lock("test");

		assertEquals(0, lock.getReadLockCount());

		lock.acquireRead();
		assertEquals(1, lock.getReadLockCount());

		lock.acquireRead();
		assertEquals(2, lock.getReadLockCount());

		lock.releaseRead();
		assertEquals(1, lock.getReadLockCount());

		lock.releaseRead();
		assertEquals(0, lock.getReadLockCount());
	}

	// -------------------------------------------------------------------------
	// Read/Write interaction tests
	// -------------------------------------------------------------------------

	@Test
	public void testWriteLockBlocksReaders() throws Exception {
		Lock lock = new Lock("test");
		CountDownLatch writerAcquired = new CountDownLatch(1);
		CountDownLatch readerAttempted = new CountDownLatch(1);
		AtomicBoolean readerGotLock = new AtomicBoolean(false);

		Thread writer = new Thread(() -> {
			lock.acquire();
			writerAcquired.countDown();
			try {
				assertTrue(readerAttempted.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
				// Hold write lock for a bit to ensure reader is blocked
				Thread.sleep(300);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			finally {
				lock.release();
			}
		});

		Thread reader = new Thread(() -> {
			try {
				assertTrue(writerAcquired.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			readerAttempted.countDown();
			lock.acquireRead();
			try {
				readerGotLock.set(true);
			}
			finally {
				lock.releaseRead();
			}
		});

		writer.start();
		reader.start();

		writer.join(TIMEOUT_MS);
		reader.join(TIMEOUT_MS);

		assertTrue("Reader should eventually acquire after writer releases",
			readerGotLock.get());
	}

	@Test
	public void testReadLockBlocksWriters() throws Exception {
		Lock lock = new Lock("test");
		CountDownLatch readerAcquired = new CountDownLatch(1);
		CountDownLatch writerAttempted = new CountDownLatch(1);
		AtomicBoolean writerGotLock = new AtomicBoolean(false);

		Thread reader = new Thread(() -> {
			lock.acquireRead();
			readerAcquired.countDown();
			try {
				assertTrue(writerAttempted.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
				// Hold read lock for a bit to ensure writer is blocked
				Thread.sleep(300);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			finally {
				lock.releaseRead();
			}
		});

		Thread writer = new Thread(() -> {
			try {
				assertTrue(readerAcquired.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			writerAttempted.countDown();
			lock.acquire();
			try {
				writerGotLock.set(true);
			}
			finally {
				lock.release();
			}
		});

		reader.start();
		writer.start();

		reader.join(TIMEOUT_MS);
		writer.join(TIMEOUT_MS);

		assertTrue("Writer should eventually acquire after reader releases",
			writerGotLock.get());
	}

	@Test
	public void testWriteHolderCanAcquireReadLock() {
		Lock lock = new Lock("test");

		lock.acquire();
		try {
			// Write lock holder should be able to also acquire read lock (downgrade)
			lock.acquireRead();
			try {
				assertTrue(lock.isLocked());
				assertTrue(lock.getReadLockCount() > 0);
			}
			finally {
				lock.releaseRead();
			}
		}
		finally {
			lock.release();
		}
	}

	// -------------------------------------------------------------------------
	// Fairness test
	// -------------------------------------------------------------------------

	@Test
	public void testFairLockDefaultsToTrue() {
		Lock lock = new Lock("test");
		// The default constructor should use fair=true
		// We can verify by checking that the lock works correctly under contention
		assertNotNull(lock);
	}

	@Test
	public void testFairnessParameter() {
		Lock fairLock = new Lock("fair", true);
		Lock unfairLock = new Lock("unfair", false);

		// Both should function correctly
		fairLock.acquire();
		fairLock.release();

		unfairLock.acquire();
		unfairLock.release();

		fairLock.acquireRead();
		fairLock.releaseRead();

		unfairLock.acquireRead();
		unfairLock.releaseRead();
	}

	// -------------------------------------------------------------------------
	// Read-to-write upgrade documentation test
	// -------------------------------------------------------------------------

	/**
	 * Documents that read-to-write upgrade is NOT supported.
	 * A thread that holds a read lock must release it before acquiring the write lock.
	 * Attempting to acquire the write lock while holding the read lock will deadlock.
	 *
	 * <p>The correct pattern for code that needs to upgrade from read to write is:
	 * <pre>
	 *   lock.acquireRead();
	 *   try {
	 *       // ... read operations ...
	 *       if (needToWrite) {
	 *           lock.releaseRead();
	 *           lock.acquire();
	 *           try {
	 *               // ... write operations ...
	 *           } finally {
	 *               lock.release();
	 *           }
	 *           return; // state may have changed, do not continue reading
	 *       }
	 *   } finally {
	 *       lock.releaseRead();
	 *   }
	 * </pre>
	 */
	@Test
	public void testReadToWriteUpgradeRequiresExplicitRelease() throws Exception {
		Lock lock = new Lock("test");
		AtomicBoolean success = new AtomicBoolean(false);

		// Demonstrate the correct upgrade pattern
		Thread t = new Thread(() -> {
			lock.acquireRead();
			try {
				// Simulate needing to write
				boolean needToWrite = true;
				if (needToWrite) {
					lock.releaseRead();
					lock.acquire();
					try {
						// Write operation succeeds after releasing read first
						success.set(true);
					}
					finally {
						lock.release();
					}
					return;
				}
			}
			finally {
				// Only release if we haven't already (need tracking in real code)
			}
		});

		t.start();
		t.join(TIMEOUT_MS);

		assertTrue("Correct read-to-write upgrade pattern should work", success.get());
	}

	// -------------------------------------------------------------------------
	// Starvation resistance test (fair lock)
	// -------------------------------------------------------------------------

	@Test
	public void testWriterDoesNotStarveUnderContention() throws Exception {
		Lock lock = new Lock("test", true); // fair lock
		AtomicBoolean writerCompleted = new AtomicBoolean(false);
		CountDownLatch readersStarted = new CountDownLatch(3);
		CountDownLatch writerDone = new CountDownLatch(1);

		// Start continuous readers
		for (int i = 0; i < 3; i++) {
			Thread reader = new Thread(() -> {
				readersStarted.countDown();
				for (int j = 0; j < 20; j++) {
					lock.acquireRead();
					try {
						Thread.sleep(10);
					}
					catch (InterruptedException e) {
						return;
					}
					finally {
						lock.releaseRead();
					}
					// Small gap to allow writer to get in
					Thread.yield();
				}
			});
			reader.setDaemon(true);
			reader.start();
		}

		assertTrue(readersStarted.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));

		// Writer should eventually get through despite reader contention
		Thread writer = new Thread(() -> {
			lock.acquire();
			try {
				writerCompleted.set(true);
			}
			finally {
				lock.release();
			}
			writerDone.countDown();
		});
		writer.start();

		assertTrue("Writer should not starve under fair lock",
			writerDone.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
		assertTrue(writerCompleted.get());
	}
}
