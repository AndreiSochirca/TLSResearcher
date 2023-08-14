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

import com.sun.jna.Structure;

/**
 * <code>pcap_stat</code>
 * 
 * @author Andrei Sochirca
 */
public class pcap_stat extends Structure {
    /**
     * number of packets transited on the network.
     */
    public int ps_recv;
    /**
     * number of packets dropped by the driver.
     */
    public int ps_drop;
    /**
     * drops by interface, not yet supported.
     */
    public int ps_ifdrop;
    
    /**
     * Constructor.
     */
    public pcap_stat() {
    }
}