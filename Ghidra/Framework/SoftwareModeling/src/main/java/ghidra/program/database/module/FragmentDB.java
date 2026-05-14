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
package ghidra.program.database.module;

import java.io.IOException;
import java.util.Iterator;

import db.DBRecord;
import db.Field;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Lock;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

/**
 *
 * Database implementation for Fragment.
 *
 */
class FragmentDB extends DatabaseObject implements ProgramFragment {

	private DBRecord record;
	private ModuleManager moduleMgr;
	private FragmentDBAdapter fragmentAdapter;
	private ParentChildDBAdapter parentChildAdapter;
	private AddressSet addrSet;
	private Lock lock;

	/**
	 * Constructor
	 * @param moduleMgr module manager
	 * @param cache fragment DB cache
	 * @param record fragment record
	 * @param addrSet fragment address set
	 */
	FragmentDB(ModuleManager moduleMgr, DBObjectCache<FragmentDB> cache, DBRecord record,
			AddressSet addrSet) {
		super(cache, record.getKey());
		this.moduleMgr = moduleMgr;
		this.record = record;
		this.addrSet = addrSet;
		fragmentAdapter = moduleMgr.getFragmentAdapter();
		parentChildAdapter = moduleMgr.getParentChildAdapter();
		lock = moduleMgr.getLock();
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = fragmentAdapter.getFragmentRecord(key);
			if (rec != null) {
				record = rec;
				addrSet = moduleMgr.getFragmentAddressSet(key);
				return true;
			}
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		return false;
	}

	@Override
	public boolean contains(CodeUnit codeUnit) {
		return contains(codeUnit.getMinAddress());
	}

	@Override
	public CodeUnitIterator getCodeUnits() {
		checkIsValid();
		return moduleMgr.getCodeUnits(this);
	}

	@Override
	public String getComment() {
		lock.acquireRead();
		try {
			checkIsValid();
			return record.getString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public String getName() {
		lock.acquireRead();
		try {
			checkIsValid();
			return record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public int getNumParents() {
		lock.acquireRead();
		try {
			checkIsValid();
			Field[] keys =
				parentChildAdapter.getParentChildKeys(-key, ParentChildDBAdapter.CHILD_ID_COL);
			return keys.length;
		}
		catch (IOException e) {
			moduleMgr.dbError(e);
		}
		finally {
			lock.releaseRead();
		}
		return 0;
	}

	@Override
	public String[] getParentNames() {
		return moduleMgr.getParentNames(-key);
	}

	@Override
	public ProgramModule[] getParents() {
		return moduleMgr.getParents(-key);
	}

	@Override
	public void move(Address min, Address max) throws NotFoundException {
		lock.acquire();
		try {
			checkDeleted();
			moduleMgr.move(this, min, max);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setComment(String comment) {
		lock.acquire();
		try {
			checkDeleted();
			String oldComments = record.getString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL);
			if (oldComments == null || !oldComments.equals(comment)) {
				record.setString(FragmentDBAdapter.FRAGMENT_COMMENTS_COL, comment);
				try {
					fragmentAdapter.updateFragmentRecord(record);
					moduleMgr.commentsChanged(oldComments, this);
				}
				catch (IOException e) {
					moduleMgr.dbError(e);
				}
			}

		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setName(String name) throws DuplicateNameException {
		lock.acquire();
		try {
			checkIsValid();
			DBRecord r = fragmentAdapter.getFragmentRecord(name);
			if (r != null) {
				if (key != r.getKey()) {
					throw new DuplicateNameException(name + " already exists");
				}
				return; // no changes
			}
			if (fragmentAdapter.getFragmentRecord(name) != null) {
				throw new DuplicateNameException(name + " already exists");
			}
			String oldName = record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
			record.setString(FragmentDBAdapter.FRAGMENT_NAME_COL, name);
			fragmentAdapter.updateFragmentRecord(record);
			moduleMgr.nameChanged(oldName, this);
		}
		catch (IOException e) {
			moduleMgr.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getTreeName() {
		return moduleMgr.getTreeName();
	}

	@Override
	public boolean contains(Address start, Address end) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.contains(start, end);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public boolean contains(Address addr) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.contains(addr);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.contains(rangeSet);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.hasSameAddresses(view);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getAddresses(forward);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getAddresses(start, forward);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getAddressRanges();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean atStart) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getAddressRanges(atStart);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Address getMaxAddress() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getMaxAddress();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Address getMinAddress() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getMinAddress();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public long getNumAddresses() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getNumAddresses();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public int getNumAddressRanges() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getNumAddressRanges();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersect(view);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersectRange(start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersects(Address start, Address end) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersects(start, end);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersects(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.intersects(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isEmpty() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.isEmpty();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressSet subtract(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.subtract(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet union(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.union(set);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSet xor(AddressSetView set) {
		lock.acquire();
		try {
			checkIsValid();
			return addrSet.xor(set);
		}
		finally {
			lock.release();
		}
	}

	ModuleManager getModuleManager() {
		return moduleMgr;
	}

	void addRange(AddressRange range) {
		addrSet.add(range);
	}

	void removeRange(AddressRange range) {
		addrSet.delete(range);
	}

	@Override
	public String toString() {
		String name = record.getString(FragmentDBAdapter.FRAGMENT_NAME_COL);
		return name + ": " + addrSet.toString();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getAddressRanges(start, forward);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressRange getFirstRange() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getFirstRange();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressRange getLastRange() {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getLastRange();
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.getRangeContaining(address);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.iterator(forward);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.iterator(start, forward);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		lock.acquireRead();
		try {
			checkIsValid();
			return addrSet.findFirstAddressInCommon(set);
		}
		finally {
			lock.releaseRead();
		}
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(lock);
	}
}
