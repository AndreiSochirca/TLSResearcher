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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * <code>pcap_addr</code> - representation of an interface address.
 * 
 * @author Andrei Sochirca
 */
@Structure.FieldOrder({"next", "addr", "netmask", "broadaddr", "dstaddr"})
public class pcap_addr extends Structure {
	/**
	 * <code>ByReference</code>
	 */
	public static class ByReference extends pcap_addr implements Structure.ByReference {
		/**
		 * Constructor.
		 */
		public ByReference() {
		}

		/**
		 * Constructor.
		 * 
		 * @param pointer
		 */
		public ByReference(final Pointer pointer) {
			super(pointer);
		}
	}

	/**
	 * if not NULL, a pointer to the next element in the list; NULL for the last
	 * element of the list.
	 */
	public pcap_addr.ByReference next;
	/**
	 * struct sockaddr containing an address.
	 */
	public sockaddr.ByReference addr;
	/**
	 * if not NULL, a struct sockaddr that contains the netmask corresponding to the
	 * address pointed to by addr.
	 */
	public sockaddr.ByReference netmask;
	/**
	 * if not NULL, a pointer to a struct sockaddr that contains the broadcast
	 * address corresponding to the address pointed to by addr; may be null if the
	 * interface doesn't support broadcasts.
	 */
	public sockaddr.ByReference broadaddr;
	/**
	 * if not NULL, a pointer to a struct sockaddr that contains the destination
	 * address corresponding to the address pointed to by addr; may be null if the
	 * interface isn't a point- to-point interface.
	 */
	public sockaddr.ByReference dstaddr;

	/**
	 * Constructor.
	 */
	public pcap_addr() {
	}

	/**
	 * Constructor.
	 * 
	 * @param pointer
	 */
	public pcap_addr(final Pointer pointer) {
		super(pointer);
	}
}