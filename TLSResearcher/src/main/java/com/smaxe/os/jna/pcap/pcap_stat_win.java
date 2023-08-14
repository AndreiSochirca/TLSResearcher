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

/**
 * <code>pcap_stat_win</code> 
 * 
 * @author Andrei Sochirca
 */
public class pcap_stat_win extends pcap_stat {
    // fields
    /**
     * number of packets captured, i.e number of packets that are accepted by the filter,
     * that find place in the kernel buffer and therefore that actually reach the application.
     */
    public int bs_capt;
    
    /**
     * Constructor.
     */
    public pcap_stat_win() {
    }
}