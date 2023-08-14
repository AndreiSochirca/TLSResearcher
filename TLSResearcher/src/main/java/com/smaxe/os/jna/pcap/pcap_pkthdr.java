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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * <code>pcap_pkthdr</code>
 * <p>Note: Header of a packet in the dump file.
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different packet interfaces.
 * 
 * @author Andrei Sochirca
 */
@Structure.FieldOrder({"tv_sec", "tv_usec", "caplen", "len"})
public final class pcap_pkthdr extends Structure {
    /**
     * represents the number of whole seconds of elapsed time.
     */
    public NativeLong tv_sec;
    /**
     * the rest of the elapsed time (a fraction of a second),
     * represented as the number of microseconds. It is always less than one million.
     */
    public NativeLong tv_usec;
    /**
     * length of portion present.
     */
    public int caplen;
    /**
     * length this packet (off wire).
     */
    public int len;
    
    /**
     * Constructor.
     */
    public pcap_pkthdr() {
    	super();
    }
    
	/**
	 * Constructor.
	 * 
	 * @param pointer
	 */
	public pcap_pkthdr(Pointer pointer) {
		super(pointer);
	}
}