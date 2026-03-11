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

import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Ghidra synchronization lock. This class allows creation of named locks for
 * synchronizing modification of multiple tables in the Ghidra database.
 * <p>
 * This implementation uses a {@link ReentrantReadWriteLock} internally to support
 * concurrent read access while maintaining exclusive write access. The existing
 * {@link #acquire()}/{@link #release()} methods act as write lock operations for
 * backward compatibility. New {@link #acquireRead()}/{@link #releaseRead()} methods
 * allow multiple threads to hold read locks concurrently.
 * <p>
 * <b>Important:</b> {@link ReentrantReadWriteLock} does NOT support upgrading from a
 * read lock to a write lock. Any code path that holds a read lock and needs to write
 * must first release the read lock, then acquire the write lock. Attempting to acquire
 * a write lock while holding a read lock will cause a deadlock.
 * <p>
 * A thread that holds the write lock can also acquire read locks (lock downgrading is
 * supported). A thread that holds the write lock can re-acquire the write lock
 * (reentrant behavior is preserved).
 */
public class Lock {
	private final ReentrantReadWriteLock rwLock;
	private final String name;

	/**
	 * Creates an instance of a lock for synchronization within Ghidra.
	 * Uses fair ordering by default to prevent starvation under high contention.
	 * 
	 * @param name the name of this lock
	 */
	public Lock(String name) {
		this(name, true);
	}

	/**
	 * Creates an instance of a lock for synchronization within Ghidra.
	 * 
	 * @param name the name of this lock
	 * @param fairness if true, the lock uses a fair ordering policy where threads
	 *        acquire locks in the order they requested them, preventing starvation
	 *        under high contention. If false, no ordering guarantees are made
	 *        (may improve throughput at the cost of potential starvation).
	 */
	public Lock(String name, boolean fairness) {
		this.name = name;
		this.rwLock = new ReentrantReadWriteLock(fairness);
	}

	/**
	 * Acquire the write lock for exclusive access. (i.e. begin synchronizing on this
	 * named lock for a mutating operation.)
	 * <p>
	 * This method blocks until the write lock is available. The write lock is reentrant:
	 * a thread that already holds the write lock can re-acquire it. A thread that holds
	 * a read lock must release it before acquiring the write lock to avoid deadlock.
	 * <p>
	 * This is the equivalent of the original {@code acquire()} behavior and should be
	 * used for all write/mutating operations.
	 */
	public void acquire() {
		rwLock.writeLock().lock();
	}

	/**
	 * Releases the write lock, since you are through with the code that needed
	 * exclusive synchronization.
	 * 
	 * @throws IllegalStateException if the current thread does not hold the write lock
	 */
	public void release() {
		if (!rwLock.isWriteLockedByCurrentThread()) {
			throw new IllegalStateException("Attempted to release an unowned lock: " + name);
		}
		rwLock.writeLock().unlock();
	}

	/**
	 * Acquire a read lock for shared (non-exclusive) access. Multiple threads can hold
	 * read locks concurrently, allowing parallel read-only operations.
	 * <p>
	 * This method blocks if a thread currently holds or is waiting for the write lock
	 * (under fair ordering). A thread that holds the write lock can also acquire the
	 * read lock (lock downgrading).
	 * <p>
	 * <b>Important:</b> Do NOT attempt to acquire a write lock while holding a read lock.
	 * {@link ReentrantReadWriteLock} does not support lock upgrading and this will cause
	 * a deadlock. Release the read lock first, then acquire the write lock.
	 */
	public void acquireRead() {
		rwLock.readLock().lock();
	}

	/**
	 * Releases a read lock previously acquired via {@link #acquireRead()}.
	 */
	public void releaseRead() {
		rwLock.readLock().unlock();
	}

	/**
	 * Gets the thread that currently owns the write lock.
	 * 
	 * @return the thread that owns the write lock or null if no thread holds it.
	 */
	public Thread getOwner() {
		return rwLock.isWriteLockedByCurrentThread() ? Thread.currentThread() : null;
	}

	/**
	 * Checks whether the write lock is currently held by any thread.
	 * 
	 * @return true if the write lock is held by any thread.
	 */
	public boolean isLocked() {
		return rwLock.isWriteLocked();
	}

	/**
	 * Returns the number of read locks currently held.
	 * 
	 * @return the number of read locks held
	 */
	public int getReadLockCount() {
		return rwLock.getReadLockCount();
	}

	/**
	 * Returns the number of reentrant write holds on this lock by the current thread.
	 * 
	 * @return the number of holds on the write lock by the current thread, or zero if
	 *         the write lock is not held by the current thread
	 */
	public int getWriteHoldCount() {
		return rwLock.getWriteHoldCount();
	}
}
