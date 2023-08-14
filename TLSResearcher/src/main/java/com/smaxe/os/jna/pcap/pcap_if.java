/**
 * Copyright (c) 2009 Andrei Sochirca, All Rights Reserved
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.  
 */
package com.smaxe.os.jna.pcap;

import com.sun.jna.*;

/**
 * <code>pcap_if</code> - item in a list of interfaces, used by pcap_findalldevs().
 * 
 * @author Andrei Sochirca
 */
@Structure.FieldOrder({"next", "name", "description", "addresses", "flags"})
public class pcap_if extends Structure {
	/**
	 * <code>ByReference</code>
	 */
	public static class ByReference extends pcap_if implements Structure.ByReference {
		/**
		 * Constructor.
		 */
		public ByReference() {
		}
	}

	/**
	 * if not NULL, a pointer to the next element in the list; NULL for the last
	 * element of the list.
	 */
	public pcap_if.ByReference next;
	/**
	 * string giving a name for the device to pass to pcap_open_live().
	 */
	public String name;
	/**
	 * string giving a human-readable description of the device.
	 */
	public String description;
	/**
	 * first element of a list of addresses for the interface.
	 */
	public pcap_addr.ByReference addresses;
	/**
	 * PCAP_IF_ interface flags. Currently the only possible flag is
	 * PCAP_IF_LOOPBACK, that is set if the interface is a loopback interface.
	 */
	public int flags;

	/**
	 * Constructor.
	 */
	public pcap_if() {
	}

	/**
	 * Constructor.
	 * 
	 * @param pointer
	 */
	public pcap_if(Pointer pointer) {
		super(pointer);
	}

	/**
	 * @return next
	 */
	public pcap_if next() {
		if (next == null) return null;
		
		next.read();
		
		return next;
	}
}